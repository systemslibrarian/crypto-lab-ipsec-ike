import { createCipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  readU32be,
  u32be,
  u64be,
  utf8,
} from "./bytes";
import {
  ESP_MAX_SEQUENCE,
  EspSender,
  commitReplay,
  createChildSaPair,
  createEspSa,
  createReplayWindow,
  installSa,
  receiveEspPacket,
  replayPrecheck,
  retireSa,
  type EspSa,
} from "./esp";
import { aesGcmSeal } from "./primitives";

const KEYMAT = hexToBytes("000102030405060708090a0b0c0d0e0fa0a1a2a3");
const SPI = 0x10203040;

function sa(overrides: Partial<EspSa> = {}): EspSa {
  return {
    ...createEspSa({
      spi: SPI,
      keyWithSalt: KEYMAT,
      direction: "initiator-to-responder",
    }),
    ...overrides,
  };
}

describe("64-packet ESP replay window", () => {
  it("accepts valid reordering and then refuses a duplicate", () => {
    let window = createReplayWindow();
    window = commitReplay(window, 1);
    window = commitReplay(window, 3);
    expect(replayPrecheck(window, 2)).toBe(true);
    window = commitReplay(window, 2);
    expect(replayPrecheck(window, 2)).toBe("replay");
    expect(window.highest).toBe(3);
    expect(window.bitmap & 0b111n).toBe(0b111n);
  });

  it("moves its floor and refuses too-old and invalid values", () => {
    let window = createReplayWindow();
    window = commitReplay(window, 1);
    window = commitReplay(window, 65);
    expect(replayPrecheck(window, 1)).toBe("too-old");
    expect(replayPrecheck(window, 2)).toBe(true);
    expect(replayPrecheck(window, 0)).toBe("invalid-sequence");
    expect(replayPrecheck(window, ESP_MAX_SEQUENCE + 1)).toBe(
      "invalid-sequence",
    );
  });

  it("rejects invalid window state", () => {
    expect(() =>
      replayPrecheck({ highest: -1, bitmap: 0n, size: 64 }, 1),
    ).toThrow(/window/);
    expect(() => createReplayWindow(0)).toThrow(/size/);
    expect(() =>
      replayPrecheck({ highest: 5, bitmap: 0n, size: 64 }, 5),
    ).toThrow(/Impossible/);
    expect(() =>
      replayPrecheck({ highest: 5, bitmap: 0b100001n, size: 64 }, 4),
    ).toThrow(/Impossible/);
  });
});

describe("AES-GCM-16 ESP packet processing", () => {
  it("sends sequence one first and matches an independent Node AES-GCM packet", async () => {
    const payload = utf8("bounded ESP packet");
    const sealed = await new EspSender(sa()).send(payload, 17);
    expect(sealed.sequence).toBe(1);
    expect(readU32be(sealed.packet, 0)).toBe(SPI);
    expect(readU32be(sealed.packet, 4)).toBe(1);
    expect(sealed.aad).toEqual(concatBytes(u32be(SPI), u32be(1)));
    expect(sealed.explicitIv).toEqual(u64be(1n));
    expect(sealed.nonce).toEqual(concatBytes(KEYMAT.slice(16), u64be(1n)));

    const reference = createCipheriv(
      "aes-128-gcm",
      KEYMAT.slice(0, 16),
      sealed.nonce,
    );
    reference.setAAD(sealed.aad);
    const ciphertext = Buffer.concat([
      reference.update(sealed.plaintext),
      reference.final(),
    ]);
    expect(sealed.ciphertext).toEqual(new Uint8Array(ciphertext));
    expect(sealed.tag).toEqual(new Uint8Array(reference.getAuthTag()));
    expect(sealed.packet).toEqual(
      concatBytes(sealed.aad, sealed.explicitIv, sealed.ciphertext, sealed.tag),
    );
  });

  it("looks up the SPI, prechecks replay, authenticates, then commits", async () => {
    const first = await new EspSender(sa()).send(utf8("one"), 6);
    const sad = installSa(new Map(), sa());
    const accepted = await receiveEspPacket(sad, first.packet);
    expect(accepted.accepted).toBe(true);
    if (!accepted.accepted) throw new Error("fixture should be accepted");
    expect(accepted.payload).toEqual(utf8("one"));
    expect(accepted.nextHeader).toBe(6);
    expect(accepted.windowBefore.highest).toBe(0);
    expect(accepted.windowAfter.highest).toBe(1);

    const replay = await receiveEspPacket(accepted.sad, first.packet);
    expect(replay).toMatchObject({ accepted: false, stage: "replay-precheck" });
    if (replay.accepted) throw new Error("fixture should be refused");
    expect(replay.windowAfter).toEqual(replay.windowBefore);
  });

  it("does not advance the window for a modified packet ahead of it", async () => {
    const outbound = new EspSender(sa());
    let sad = installSa(new Map(), sa());
    for (let sequence = 1; sequence <= 3; sequence += 1) {
      const sealed = await outbound.send(Uint8Array.of(sequence), 17);
      const accepted = await receiveEspPacket(sad, sealed.packet);
      expect(accepted.accepted).toBe(true);
      sad = accepted.sad;
    }
    const aheadSa = { ...outbound.snapshot(), sequenceCounter: 69 };
    const ahead = await new EspSender(aheadSa).send(utf8("tamper me"), 17);
    const modified = ahead.packet.slice();
    modified[20] = modified[20]! ^ 1;
    const refused = await receiveEspPacket(sad, modified);
    expect(refused).toMatchObject({
      accepted: false,
      stage: "authentication",
      sequence: 70,
    });
    if (refused.accepted) throw new Error("fixture should be refused");
    expect(refused.windowBefore?.highest).toBe(3);
    expect(refused.windowAfter?.highest).toBe(3);
    expect(refused.sad.get(SPI)?.replayWindow.highest).toBe(3);
  });

  it("consumes an authenticated sequence before refusing a malformed trailer", async () => {
    const inbound = sa();
    const aad = concatBytes(u32be(SPI), u32be(1));
    const explicitIv = u64be(1n);
    const nonce = concatBytes(inbound.salt, explicitIv);
    // Pad length says two, but the authenticated bytes are not canonical 01 02.
    const plaintext = concatBytes(utf8("data"), Uint8Array.of(9, 9, 2, 17));
    const sealed = await aesGcmSeal(inbound.key, nonce, plaintext, aad);
    const packet = concatBytes(aad, explicitIv, sealed.ciphertext, sealed.tag);
    const sad = installSa(new Map(), inbound);
    const malformed = await receiveEspPacket(sad, packet);
    expect(malformed).toMatchObject({ accepted: false, stage: "trailer" });
    if (malformed.accepted) throw new Error("fixture should be refused");
    expect(malformed.windowBefore?.highest).toBe(0);
    expect(malformed.windowAfter?.highest).toBe(1);
    expect(malformed.sad.get(SPI)?.replayWindow.highest).toBe(1);
    expect(await receiveEspPacket(malformed.sad, packet)).toMatchObject({
      accepted: false,
      stage: "replay-precheck",
    });
  });

  it("refuses authenticated nonminimal and unaligned profile padding", async () => {
    const inbound = sa();
    const sealMalformed = async (sequence: number, plaintext: Uint8Array) => {
      const aad = concatBytes(u32be(SPI), u32be(sequence));
      const explicitIv = u64be(BigInt(sequence));
      const nonce = concatBytes(inbound.salt, explicitIv);
      const sealed = await aesGcmSeal(inbound.key, nonce, plaintext, aad);
      return concatBytes(aad, explicitIv, sealed.ciphertext, sealed.tag);
    };
    const nonminimal = await sealMalformed(
      1,
      concatBytes(utf8("ok"), Uint8Array.of(1, 2, 3, 4), Uint8Array.of(4, 17)),
    );
    let sad = installSa(new Map(), inbound);
    const nonminimalResult = await receiveEspPacket(sad, nonminimal);
    expect(nonminimalResult).toMatchObject({
      accepted: false,
      stage: "trailer",
      reason: expect.stringMatching(/not minimal/),
    });
    sad = nonminimalResult.sad;

    const unaligned = await sealMalformed(
      2,
      concatBytes(utf8("x"), Uint8Array.of(0, 17)),
    );
    expect(await receiveEspPacket(sad, unaligned)).toMatchObject({
      accepted: false,
      stage: "trailer",
      reason: expect.stringMatching(/four-octet/),
    });
  });

  it("refuses an unknown SPI before replay or authentication", async () => {
    const sealed = await new EspSender(sa()).send(utf8("payload"), 17);
    const unknown = sealed.packet.slice();
    unknown.set(u32be(0x55667788), 0);
    const result = await receiveEspPacket(new Map([[SPI, sa()]]), unknown);
    expect(result).toMatchObject({
      accepted: false,
      stage: "sad-lookup",
      spi: 0x55667788,
    });
  });

  it("supports valid reordering in the actual receiver", async () => {
    const outbound = new EspSender(sa());
    const packets = [];
    for (const text of ["one", "two", "three"]) {
      const sealed = await outbound.send(utf8(text), 17);
      packets.push(sealed.packet);
    }
    let sad = installSa(new Map(), sa());
    for (const index of [0, 2, 1]) {
      const result = await receiveEspPacket(sad, packets[index]!);
      expect(result.accepted).toBe(true);
      sad = result.sad;
    }
    expect(sad.get(SPI)!.replayWindow.bitmap & 0b111n).toBe(0b111n);
  });

  it("enforces the actual receiver's 64-packet floor without rejecting an unseen edge packet", async () => {
    const outbound = new EspSender(sa());
    const packets = [];
    for (let sequence = 1; sequence <= 65; sequence += 1) {
      packets.push((await outbound.send(Uint8Array.of(sequence), 17)).packet);
    }
    const sad = installSa(new Map(), sa());
    const newest = await receiveEspPacket(sad, packets[64]!);
    expect(newest.accepted).toBe(true);
    if (!newest.accepted) throw new Error("fixture should be accepted");

    expect(await receiveEspPacket(newest.sad, packets[0]!)).toMatchObject({
      accepted: false,
      stage: "replay-precheck",
      reason: expect.stringContaining("too-old"),
    });
    const edge = await receiveEspPacket(newest.sad, packets[1]!);
    expect(edge.accepted).toBe(true);
    if (!edge.accepted) throw new Error("edge fixture should be accepted");
    expect(edge.windowAfter.highest).toBe(65);
  });

  it("refuses repeat nonce state and sequence wrap", async () => {
    const nonce = concatBytes(KEYMAT.slice(16), u64be(1n));
    await expect(
      new EspSender(sa({ usedNonces: [bytesToHex(nonce)] })).send(
        utf8("repeat"),
        17,
      ),
    ).rejects.toThrow(/Repeated AES-GCM nonce/);
    await expect(
      new EspSender(sa({ sequenceCounter: ESP_MAX_SEQUENCE })).send(
        utf8("wrap"),
        17,
      ),
    ).rejects.toThrow(/before wrap/);

    const last = new EspSender(sa({ sequenceCounter: ESP_MAX_SEQUENCE - 1 }));
    expect((await last.send(utf8("last"), 17)).sequence).toBe(ESP_MAX_SEQUENCE);
    await expect(last.send(utf8("wrapped"), 17)).rejects.toThrow(/before wrap/);
  });

  it("burns a reserved sequence after AEAD invocation fails", async () => {
    let attempts = 0;
    const sender = new EspSender(sa(), async (key, nonce, plaintext, aad) => {
      attempts += 1;
      if (attempts === 1) throw new Error("synthetic Web Crypto failure");
      return aesGcmSeal(key, nonce, plaintext, aad);
    });
    await expect(sender.send(utf8("first"), 17)).rejects.toThrow(/synthetic/);
    expect(sender.snapshot().sequenceCounter).toBe(1);
    expect(sender.snapshot().usedNonces).toHaveLength(1);

    await expect(sender.send(utf8("invalid"), 256)).rejects.toThrow(/octet/);
    expect(sender.snapshot().sequenceCounter).toBe(1);

    const second = await sender.send(utf8("second"), 17);
    expect(second.sequence).toBe(2);
    expect(second.explicitIv).toEqual(u64be(2n));
  });
});

describe("Child-SA directions and rekey", () => {
  const oldPair = createChildSaPair({
    initiatorToResponderKeymat: KEYMAT,
    responderToInitiatorKeymat: hexToBytes(
      "101112131415161718191a1b1c1d1e1fb0b1b2b3",
    ),
    responderInboundSpi: 0x11111111,
    initiatorInboundSpi: 0x22222222,
    generation: 1,
  });
  const newPair = createChildSaPair({
    initiatorToResponderKeymat: hexToBytes(
      "202122232425262728292a2b2c2d2e2fc0c1c2c3",
    ),
    responderToInitiatorKeymat: hexToBytes(
      "303132333435363738393a3b3c3d3e3fd0d1d2d3",
    ),
    responderInboundSpi: 0x33333333,
    initiatorInboundSpi: 0x44444444,
    generation: 2,
  });

  it("uses receiver-chosen SPIs and the I-to-R-first KEYMAT ordering", () => {
    expect(oldPair.initiatorToResponder.spi).toBe(0x11111111);
    expect(oldPair.initiatorToResponder.key).toEqual(KEYMAT.slice(0, 16));
    expect(oldPair.responderToInitiator.spi).toBe(0x22222222);
    expect(oldPair.initiatorToResponder.direction).toBe(
      "initiator-to-responder",
    );
  });

  it("keeps old/new overlap, then refuses the retired SPI", async () => {
    let sad = installSa(new Map(), oldPair.initiatorToResponder);
    sad = installSa(sad, newPair.initiatorToResponder);
    const oldPacket = await new EspSender(oldPair.initiatorToResponder).send(
      utf8("old overlap"),
      17,
    );
    const newPacket = await new EspSender(newPair.initiatorToResponder).send(
      utf8("new overlap"),
      17,
    );
    expect((await receiveEspPacket(sad, oldPacket.packet)).accepted).toBe(true);
    expect((await receiveEspPacket(sad, newPacket.packet)).accepted).toBe(true);
    expect(newPacket.sequence).toBe(1);

    sad = retireSa(sad, oldPair.initiatorToResponder.spi);
    expect(await receiveEspPacket(sad, oldPacket.packet)).toMatchObject({
      accepted: false,
      stage: "sad-lookup",
    });
  });

  it("rejects a new SPI packet sealed under the old generation key", async () => {
    const oldSender = new EspSender(oldPair.initiatorToResponder);
    const wrongGeneration = await oldSender.sendWithReceiverSpiControl(
      utf8("wrong key"),
      17,
      newPair.initiatorToResponder.spi,
    );
    const actualSad = installSa(new Map(), newPair.initiatorToResponder);
    expect(
      await receiveEspPacket(actualSad, wrongGeneration.packet),
    ).toMatchObject({ accepted: false, stage: "authentication" });

    const explanatoryOldKeySa = {
      ...oldPair.initiatorToResponder,
      spi: newPair.initiatorToResponder.spi,
      generation: 2,
    };
    const explanatorySad = installSa(new Map(), explanatoryOldKeySa);
    expect(
      await receiveEspPacket(explanatorySad, wrongGeneration.packet),
    ).toMatchObject({ accepted: true, stage: "accepted" });
    expect(wrongGeneration.aad.slice(0, 4)).toEqual(
      u32be(newPair.initiatorToResponder.spi),
    );
    expect(oldSender.snapshot().sequenceCounter).toBe(1);
  });

  it("refuses duplicate installs and invalid retirement", () => {
    const sad = installSa(new Map(), oldPair.initiatorToResponder);
    expect(() => installSa(sad, oldPair.initiatorToResponder)).toThrow(
      /already/,
    );
    expect(() => retireSa(sad, 0x99999999)).toThrow(/not installed/);
  });

  it("keeps installed, updated, and retired SAD records isolated from caller mutation", async () => {
    const source = sa();
    const installed = installSa(new Map(), source);
    source.key[0] = 0xff;
    source.salt[0] = 0xff;
    source.replayWindow.highest = 44;
    (source.usedNonces as string[]).push("mutated");
    expect(installed.get(SPI)?.key[0]).toBe(KEYMAT[0]);
    expect(installed.get(SPI)?.salt[0]).toBe(KEYMAT[16]);
    expect(installed.get(SPI)?.replayWindow.highest).toBe(0);
    expect(installed.get(SPI)?.usedNonces).toEqual([]);

    const packet = await new EspSender(sa()).send(utf8("isolation"), 17);
    const accepted = await receiveEspPacket(installed, packet.packet);
    expect(accepted.accepted).toBe(true);
    const installedKey = installed.get(SPI)!.key;
    installedKey[1] = 0xee;
    expect(accepted.sad.get(SPI)?.key[1]).toBe(KEYMAT[1]);

    const retired = retireSa(accepted.sad, SPI);
    accepted.sad.get(SPI)!.salt[1] = 0xdd;
    expect(retired.get(SPI)?.salt[1]).toBe(KEYMAT[17]);
    expect(retired.get(SPI)?.active).toBe(false);
  });

  it("snapshots the caller SAD before asynchronous authentication", async () => {
    const outbound = new EspSender(sa());
    const sealed = await outbound.send(utf8("snapshot the inbound SA"), 17);
    const callerSad = installSa(new Map(), sa());
    const callerRecord = callerSad.get(SPI)!;
    const pending = receiveEspPacket(callerSad, sealed.packet);
    callerRecord.key.fill(0xff);
    callerRecord.active = false;
    callerRecord.generation = 99;
    callerSad.delete(SPI);

    const result = await pending;
    expect(result).toMatchObject({ accepted: true, stage: "accepted" });
    expect(result.sad.get(SPI)).toMatchObject({
      active: true,
      generation: 1,
    });
    expect(result.sad.get(SPI)?.key).toEqual(KEYMAT.slice(0, 16));
  });
});
