import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes, readU16be, u64be } from "./bytes";
import { FIXED_EXPECTED, fixedHandshakeInputs } from "./fixtures";
import { runIkeHandshake } from "./ike";
import {
  ExchangeType,
  PayloadType,
  USE_TRANSPORT_MODE,
  encodeTsBody,
} from "./ike-wire";
import {
  REKEY_SA,
  deriveChildRekeyKeys,
  runChildSaRekey,
  runChildSaDelete,
  sealChildSaDelete,
  type ChildRekeyInputs,
} from "./rekey";

const NONCE_I2 = hexToBytes(
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
);
const NONCE_R2 = hexToBytes(
  "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
);

async function inputs(
  exchangeInitiator: ChildRekeyInputs["exchangeInitiator"] = "original-initiator",
): Promise<ChildRekeyInputs> {
  const fixed = fixedHandshakeInputs();
  const handshake = await runIkeHandshake(fixed);
  return {
    initiatorSpi: fixed.initiatorSpi,
    responderSpi: fixed.responderSpi,
    keys: handshake.keys,
    messageId: 2,
    exchangeInitiator,
    freshNonceFromExchangeInitiator: NONCE_I2,
    freshNonceFromExchangeResponder: NONCE_R2,
    newOriginalInitiatorInboundSpi: hexToBytes("c1c2c3c4"),
    newOriginalResponderInboundSpi: hexToBytes("d1d2d3d4"),
    oldOriginalInitiatorInboundSpi: 0xa1a2a3a4,
    oldOriginalResponderInboundSpi: 0xb1b2b3b4,
    activeSelector: handshake.narrowedSelector,
    originalInitiatorIkeSender: handshake.initiatorIkeSender,
    originalResponderIkeSender: handshake.responderIkeSender,
    activeMode: "tunnel",
    responderEchoesTransport: false,
  };
}

describe("bounded Child-SA rekey", () => {
  it("matches the independently derived fresh-nonce KEYMAT fixture", async () => {
    const keys = await deriveChildRekeyKeys(
      hexToBytes(FIXED_EXPECTED.skD),
      NONCE_I2,
      NONCE_R2,
    );
    expect(bytesToHex(keys.exchangeInitiatorToResponder)).toBe(
      "c577b00e80c238ce1ecbbd17b52b9eb678a29ab8",
    );
    expect(bytesToHex(keys.exchangeResponderToInitiator)).toBe(
      "2e4a2810f3968ec1a5d7e6884a2ea9c35400b989",
    );
  });

  it("executes a protected CREATE_CHILD_SA with REKEY_SA, fresh nonces, and no KE", async () => {
    const result = await runChildSaRekey(await inputs());
    expect(result.openedRequest.header.exchangeType).toBe(
      ExchangeType.CREATE_CHILD_SA,
    );
    expect(result.openedResponse.header.exchangeType).toBe(
      ExchangeType.CREATE_CHILD_SA,
    );
    expect(result.openedRequest.payloads.map(({ type }) => type)).toEqual([
      PayloadType.NOTIFY,
      PayloadType.SA,
      PayloadType.NONCE,
      PayloadType.TSI,
      PayloadType.TSR,
    ]);
    expect(result.openedResponse.payloads.map(({ type }) => type)).toEqual([
      PayloadType.SA,
      PayloadType.NONCE,
      PayloadType.TSI,
      PayloadType.TSR,
    ]);
    expect(
      result.openedRequest.payloads.some(({ type }) => type === PayloadType.KE),
    ).toBe(false);
    const notify = result.openedRequest.payloads[0]!.body;
    expect(notify[0]).toBe(3);
    expect(notify[1]).toBe(4);
    expect(readU16be(notify, 2)).toBe(REKEY_SA);
    expect(bytesToHex(notify.slice(4))).toBe("a1a2a3a4");
    expect(result.originalInitiatorInboundSpi).toBe(0xc1c2c3c4);
    expect(result.originalResponderInboundSpi).toBe(0xd1d2d3d4);
    expect(result.request.explicitIv).toEqual(u64be(2n));
    expect(result.response.explicitIv).toEqual(u64be(3n));
  });

  it("orders KEYMAT by the current exchange roles, not permanently by original IKE role", async () => {
    const originalInitiated = await runChildSaRekey(
      await inputs("original-initiator"),
    );
    const responderInputs = await inputs("original-responder");
    // Preserve the same exchange-role nonce order to isolate the role mapping.
    const responderInitiated = await runChildSaRekey(responderInputs);
    expect(responderInitiated.originalResponderToInitiator).toEqual(
      responderInitiated.exchangeInitiatorToResponder,
    );
    expect(responderInitiated.originalInitiatorToResponder).toEqual(
      responderInitiated.exchangeResponderToInitiator,
    );
    expect(originalInitiated.originalInitiatorToResponder).toEqual(
      originalInitiated.exchangeInitiatorToResponder,
    );
    expect(responderInitiated.openedRequest.header.flags & 0x08).toBe(0);
    expect(responderInitiated.openedResponse.header.flags & 0x28).toBe(0x28);
    const reversed = {
      sourceAddress: { ...responderInputs.activeSelector.destinationAddress },
      destinationAddress: { ...responderInputs.activeSelector.sourceAddress },
      sourcePort: { ...responderInputs.activeSelector.destinationPort },
      destinationPort: { ...responderInputs.activeSelector.sourcePort },
      protocol: responderInputs.activeSelector.protocol,
    };
    expect(responderInitiated.openedRequest.payloads[3]!.body).toEqual(
      encodeTsBody(reversed, "source"),
    );
    expect(responderInitiated.openedRequest.payloads[4]!.body).toEqual(
      encodeTsBody(reversed, "destination"),
    );
    expect(responderInitiated.openedResponse.payloads[2]!.body).toEqual(
      encodeTsBody(reversed, "source"),
    );
    expect(responderInitiated.openedResponse.payloads[3]!.body).toEqual(
      encodeTsBody(reversed, "destination"),
    );
  });

  it("requires transport request and echo again during a transport-SA rekey", async () => {
    const transport = await inputs();
    transport.activeMode = "transport";
    transport.responderEchoesTransport = true;
    const accepted = await runChildSaRekey(transport);
    expect(accepted.childState).toBe("established");
    expect(accepted.modeAfter).toBe("transport");
    expect(readU16be(accepted.openedRequest.payloads.at(-1)!.body, 2)).toBe(
      USE_TRANSPORT_MODE,
    );
    expect(readU16be(accepted.openedResponse.payloads.at(-1)!.body, 2)).toBe(
      USE_TRANSPORT_MODE,
    );

    const noEcho = await inputs();
    noEcho.activeMode = "transport";
    noEcho.responderEchoesTransport = false;
    const refusedFallback = await runChildSaRekey(noEcho);
    expect(refusedFallback.modeAfter).toBe("tunnel");
    expect(refusedFallback.childState).toBe("delete-required");
  });

  it("seals a protected Child-SA Delete naming the sender's expected inbound SPI", async () => {
    const rekeyInputs = await inputs();
    await runChildSaRekey(rekeyInputs);
    const deletion = await runChildSaDelete({
      requester: "original-initiator",
      messageId: 3,
      keys: rekeyInputs.keys,
      originalInitiatorIkeSender: rekeyInputs.originalInitiatorIkeSender,
      originalResponderIkeSender: rekeyInputs.originalResponderIkeSender,
      originalInitiatorInboundSpi: rekeyInputs.oldOriginalInitiatorInboundSpi,
      originalResponderInboundSpi: rekeyInputs.oldOriginalResponderInboundSpi,
    });
    expect(deletion.request.firstInnerPayload).toBe(PayloadType.DELETE);
    expect(deletion.response.firstInnerPayload).toBe(PayloadType.DELETE);
    expect(deletion.openedRequest.payloads[0]!.body.slice(0, 4)).toEqual(
      Uint8Array.of(3, 4, 0, 1),
    );
    expect(bytesToHex(deletion.openedRequest.payloads[0]!.body.slice(4))).toBe(
      "a1a2a3a4",
    );
    expect(bytesToHex(deletion.openedResponse.payloads[0]!.body.slice(4))).toBe(
      "b1b2b3b4",
    );
  });

  it("uses independent requester Message-ID spaces and refuses invalid values", async () => {
    const responderFirst = await inputs("original-responder");
    responderFirst.messageId = 0;
    expect(
      (await runChildSaRekey(responderFirst)).openedRequest.header.messageId,
    ).toBe(0);

    const invalid = await inputs();
    invalid.newOriginalResponderInboundSpi =
      invalid.newOriginalInitiatorInboundSpi;
    await expect(runChildSaRekey(invalid)).rejects.toThrow(/distinct/);
    invalid.newOriginalResponderInboundSpi = hexToBytes("d1d2d3d4");
    invalid.messageId = 1;
    await expect(runChildSaRekey(invalid)).rejects.toThrow(
      /follows request Message IDs/,
    );

    const invalidResponder = await inputs("original-responder");
    invalidResponder.messageId = -1;
    await expect(runChildSaRekey(invalidResponder)).rejects.toThrow(
      /independent/,
    );
  });

  it("validates fresh nonces and SPIs before allocating protected-message IVs", async () => {
    const invalidNonce = await inputs();
    invalidNonce.freshNonceFromExchangeInitiator = new Uint8Array(15);
    const before = invalidNonce.originalInitiatorIkeSender.currentIvCounter;
    await expect(runChildSaRekey(invalidNonce)).rejects.toThrow(/nonce/);
    expect(invalidNonce.originalInitiatorIkeSender.currentIvCounter).toBe(
      before,
    );

    const reusedSpi = await inputs();
    reusedSpi.newOriginalInitiatorInboundSpi = hexToBytes("a1a2a3a4");
    await expect(runChildSaRekey(reusedSpi)).rejects.toThrow(/fresh SPIs/);

    const reservedSpi = await inputs();
    reservedSpi.newOriginalResponderInboundSpi = hexToBytes("000000ff");
    await expect(runChildSaRekey(reservedSpi)).rejects.toThrow(
      /greater than 255/,
    );

    const invalidSelector = await inputs();
    invalidSelector.activeSelector = {
      ...invalidSelector.activeSelector,
      sourcePort: { start: 9000, end: 8000 },
    };
    const selectorCounter =
      invalidSelector.originalInitiatorIkeSender.currentIvCounter;
    await expect(runChildSaRekey(invalidSelector)).rejects.toThrow(/range/);
    expect(invalidSelector.originalInitiatorIkeSender.currentIvCounter).toBe(
      selectorCounter,
    );

    const mismatchedIkeSa = await inputs();
    mismatchedIkeSa.initiatorSpi = mismatchedIkeSa.initiatorSpi.slice();
    mismatchedIkeSa.initiatorSpi[0] ^= 1;
    const initiatorCounter =
      mismatchedIkeSa.originalInitiatorIkeSender.currentIvCounter;
    const responderCounter =
      mismatchedIkeSa.originalResponderIkeSender.currentIvCounter;
    await expect(runChildSaRekey(mismatchedIkeSa)).rejects.toThrow(
      /match both sender contexts/,
    );
    expect(mismatchedIkeSa.originalInitiatorIkeSender.currentIvCounter).toBe(
      initiatorCounter,
    );
    expect(mismatchedIkeSa.originalResponderIkeSender.currentIvCounter).toBe(
      responderCounter,
    );
  });

  it("refuses a reserved Delete SPI before allocating an IKE IV", async () => {
    const rekeyInputs = await inputs();
    const before = rekeyInputs.originalInitiatorIkeSender.currentIvCounter;
    await expect(
      sealChildSaDelete({
        senderRole: "original-initiator",
        messageId: 2,
        ikeSender: rekeyInputs.originalInitiatorIkeSender,
        expectedInboundSpi: 255,
      }),
    ).rejects.toThrow(/greater than 255/);
    expect(rekeyInputs.originalInitiatorIkeSender.currentIvCounter).toBe(
      before,
    );

    const badKeys = await inputs();
    const initiatorBefore = badKeys.originalInitiatorIkeSender.currentIvCounter;
    const responderBefore = badKeys.originalResponderIkeSender.currentIvCounter;
    await expect(
      runChildSaDelete({
        requester: "original-initiator",
        messageId: 2,
        keys: { ...badKeys.keys, skEi: new Uint8Array(19) },
        originalInitiatorIkeSender: badKeys.originalInitiatorIkeSender,
        originalResponderIkeSender: badKeys.originalResponderIkeSender,
        originalInitiatorInboundSpi: badKeys.oldOriginalInitiatorInboundSpi,
        originalResponderInboundSpi: badKeys.oldOriginalResponderInboundSpi,
      }),
    ).rejects.toThrow(/SK_ei/);
    expect(badKeys.originalInitiatorIkeSender.currentIvCounter).toBe(
      initiatorBefore,
    );
    expect(badKeys.originalResponderIkeSender.currentIvCounter).toBe(
      responderBefore,
    );
  });
});
