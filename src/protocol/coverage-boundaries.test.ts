import { describe, expect, it } from "vitest";
import {
  bytesEqual,
  randomBytes,
  readU32be,
  readU64be,
  readUtf8,
  u64be,
  utf8,
} from "./bytes";
import { fixedHandshakeInputs } from "./fixtures";
import {
  IkeMessageSender,
  freshHandshakeSecrets,
  openIkeEncryptedMessage,
  prfPlus,
  runIkeHandshake,
  sealIkeEncryptedMessage,
  verifyReceivedIkeAuth,
} from "./ike";
import {
  ExchangeType,
  IKE_FLAG_INITIATOR,
  IKE_HEADER_BYTES,
  IKE_VERSION_2_0,
  PayloadType,
  decodePayloadChain,
  decodeSingleTsBody,
  encodeAuthBody,
  encodeDeleteBody,
  encodeIdBody,
  encodeIkeHeader,
  encodeIkeMessage,
  encodeKeBody,
  encodeNotifyBody,
  encodePayloadChain,
  encodeSaBody,
  encodeTsBody,
  ikeSaProposal,
  parseIkeHeader,
  payload,
} from "./ike-wire";

const INITIATOR_SPI = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
const RESPONDER_SPI = Uint8Array.of(11, 12, 13, 14, 15, 16, 17, 18);

describe("public protocol boundary validation", () => {
  it("generates allocated fresh values and rejects invalid byte inputs", () => {
    const fresh = freshHandshakeSecrets();

    expect(fresh.initiatorPrivate).toHaveLength(32);
    expect(fresh.responderPrivate).toHaveLength(32);
    expect(fresh.nonceI).toHaveLength(32);
    expect(fresh.nonceR).toHaveLength(32);
    expect(fresh.initiatorSpi).toHaveLength(8);
    expect(fresh.responderSpi).toHaveLength(8);
    expect(readU64be(fresh.initiatorSpi)).not.toBe(0n);
    expect(readU64be(fresh.responderSpi)).not.toBe(0n);
    expect(bytesEqual(fresh.initiatorSpi, fresh.responderSpi)).toBe(false);
    expect(readU32be(fresh.initiatorInboundChildSpi)).toBeGreaterThanOrEqual(
      256,
    );
    expect(readU32be(fresh.responderInboundChildSpi)).toBeGreaterThanOrEqual(
      256,
    );
    expect(
      bytesEqual(
        fresh.initiatorInboundChildSpi,
        fresh.responderInboundChildSpi,
      ),
    ).toBe(false);
    expect(fresh.initiatorIkeIv).toEqual(u64be(1n));
    expect(fresh.responderIkeIv).toEqual(u64be(1n));

    for (const length of [0, 65_537, 1.5]) {
      expect(() => randomBytes(length)).toThrow(/between 1 and 65,536/);
    }
    expect(readUtf8(utf8("strict UTF-8"))).toBe("strict UTF-8");
    expect(() => readUtf8(Uint8Array.of(0xc3, 0x28))).toThrow();
  });

  it("fails closed at IKE header, payload, proposal, and selector boundaries", () => {
    const headerOptions = {
      initiatorSpi: INITIATOR_SPI,
      responderSpi: RESPONDER_SPI,
      nextPayload: PayloadType.NONE,
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_INITIATOR,
      messageId: 2,
      length: IKE_HEADER_BYTES,
    };

    expect(() =>
      encodeIkeHeader({ ...headerOptions, length: IKE_HEADER_BYTES - 1 }),
    ).toThrow(/too short/);
    expect(() => parseIkeHeader(new Uint8Array(IKE_HEADER_BYTES - 1))).toThrow(
      /shorter than its header/,
    );
    const wrongVersion = encodeIkeHeader(headerOptions);
    wrongVersion[17] = IKE_VERSION_2_0 + 1;
    expect(() => parseIkeHeader(wrongVersion)).toThrow(/version 2.0/);

    expect(encodePayloadChain([])).toEqual({
      firstPayload: PayloadType.NONE,
      bytes: new Uint8Array(),
    });
    const critical = encodePayloadChain([
      payload(PayloadType.NOTIFY, Uint8Array.of(1), true),
    ]);
    expect(critical.bytes[1]).toBe(0x80);
    expect(() =>
      decodePayloadChain(Uint8Array.of(0), PayloadType.NONE),
    ).toThrow(/Trailing octets/);

    expect(() => encodeSaBody([])).toThrow(/at least one proposal/);
    expect(() =>
      encodeSaBody([{ number: 1, protocolId: 3, transforms: [] }]),
    ).toThrow(/at least one transform/);
    expect(() =>
      encodeSaBody([
        {
          number: 1,
          protocolId: 3,
          spi: new Uint8Array(256),
          transforms: [{ type: 1, id: 20 }],
        },
      ]),
    ).toThrow(/too large/);
    const firstProposal = ikeSaProposal();
    const alternatives = encodeSaBody([
      firstProposal,
      { ...ikeSaProposal(), number: 2 },
    ]);
    const firstProposalLength = (alternatives[2]! << 8) | alternatives[3]!;
    expect(alternatives[0]).toBe(2);
    expect(alternatives[firstProposalLength]).toBe(0);

    expect(() => encodeKeBody(31, new Uint8Array())).toThrow(
      /must not be empty/,
    );
    expect(() => encodeIdBody(1, new Uint8Array())).toThrow(
      /must not be empty/,
    );
    expect(() => encodeAuthBody(2, new Uint8Array())).toThrow(
      /must not be empty/,
    );
    expect(() =>
      encodeNotifyBody({
        messageType: 1,
        spi: new Uint8Array(256),
      }),
    ).toThrow(/too long/);
    expect(() => encodeDeleteBody(3, [])).toThrow(/between one and 65,535/);
    expect(() => encodeDeleteBody(3, [new Uint8Array()])).toThrow(
      /common nonzero size/,
    );

    const selector = fixedHandshakeInputs().offeredSelector;
    expect(() => encodeTsBody(selector, "neither" as never)).toThrow(
      /source or destination/,
    );
    const malformedTs = encodeTsBody(selector, "source").slice(1);
    expect(() => decodeSingleTsBody(malformedTs)).toThrow(
      /exactly one IPv4 address-range/,
    );
  });

  it("rejects malformed protected identities and invalid sender state", async () => {
    const inputs = fixedHandshakeInputs();
    const handshake = await runIkeHandshake(inputs);
    const verification = {
      opened: handshake.openedRequest,
      sender: "initiator" as const,
      expectedIdentity: inputs.initiatorIdentity,
      expectedInitiatorSpi: inputs.initiatorSpi,
      expectedResponderSpi: inputs.responderSpi,
      firstMessage: handshake.ikeSaInitRequest,
      peerNonce: inputs.nonceR,
      skP: handshake.keys.skPi,
      psk: inputs.psk,
    };

    const missingIdentity = {
      ...handshake.openedRequest,
      payloads: handshake.openedRequest.payloads.slice(1),
    };
    await expect(
      // A valid AEAD envelope cannot compensate for the wrong inner payload order.
      verifyReceivedIkeAuth({ ...verification, opened: missingIdentity }),
    ).resolves.toMatchObject({
      accepted: false,
      reason: expect.stringMatching(/does not begin/),
    });

    const malformedIdentity = {
      ...handshake.openedRequest,
      payloads: handshake.openedRequest.payloads.map((item, index) => ({
        ...item,
        body: index === 0 ? Uint8Array.of(1, 0, 0, 0) : item.body.slice(),
        encoded: item.encoded.slice(),
      })),
    };
    await expect(
      verifyReceivedIkeAuth({ ...verification, opened: malformedIdentity }),
    ).resolves.toMatchObject({
      accepted: false,
      reason: expect.stringMatching(/identity body is malformed/),
    });

    const malformedAuthentication = {
      ...handshake.openedRequest,
      payloads: handshake.openedRequest.payloads.map((item, index) => ({
        ...item,
        body: index === 1 ? new Uint8Array(35) : item.body.slice(),
        encoded: item.encoded.slice(),
      })),
    };
    await expect(
      verifyReceivedIkeAuth({
        ...verification,
        opened: malformedAuthentication,
      }),
    ).resolves.toMatchObject({
      accepted: false,
      reason: expect.stringMatching(/AUTH payload/),
    });

    await expect(
      prfPlus(Uint8Array.of(1), Uint8Array.of(2), -1),
    ).rejects.toThrow(/non-negative/);
    expect(
      () =>
        new IkeMessageSender({
          initiatorSpi: inputs.initiatorSpi,
          responderSpi: inputs.responderSpi,
          keyWithSalt: handshake.keys.skEi,
          originalSenderIsInitiator: true,
          initialCounter: -1n,
        }),
    ).toThrow(/unsigned 64-bit/);

    const sender = new IkeMessageSender({
      initiatorSpi: inputs.initiatorSpi,
      responderSpi: inputs.responderSpi,
      keyWithSalt: handshake.keys.skEi,
      originalSenderIsInitiator: true,
    });
    await expect(
      sender.send({
        exchangeType: ExchangeType.INFORMATIONAL,
        flags: IKE_FLAG_INITIATOR,
        messageId: 2,
        innerPayloads: [],
      }),
    ).rejects.toThrow(/cannot be empty/);
    await expect(
      sender.send({
        exchangeType: ExchangeType.INFORMATIONAL,
        flags: IKE_FLAG_INITIATOR,
        messageId: 2,
        innerPayloads: [payload(PayloadType.NOTIFY, utf8("status"))],
        paddingLength: 256,
      }),
    ).rejects.toThrow(/padding length/);
    await expect(
      sender.send({
        exchangeType: ExchangeType.INFORMATIONAL,
        flags: 0,
        messageId: 2,
        innerPayloads: [payload(PayloadType.NOTIFY, utf8("status"))],
      }),
    ).rejects.toThrow(/Initiator flag/);
    expect(sender.currentIvCounter).toBe(0n);
  });

  it("rejects invalid encrypted-message framing before releasing plaintext", async () => {
    const inputs = fixedHandshakeInputs();
    const handshake = await runIkeHandshake(inputs);
    const sealingOptions = {
      initiatorSpi: inputs.initiatorSpi,
      responderSpi: inputs.responderSpi,
      flags: IKE_FLAG_INITIATOR,
      messageId: 2,
      keyWithSalt: handshake.keys.skEi,
      explicitIv: u64be(10n),
    };

    await expect(
      sealIkeEncryptedMessage({ ...sealingOptions, innerPayloads: [] }),
    ).rejects.toThrow(/cannot be empty/);
    await expect(
      sealIkeEncryptedMessage({
        ...sealingOptions,
        innerPayloads: [payload(PayloadType.NOTIFY, utf8("status"))],
        paddingLength: 256,
      }),
    ).rejects.toThrow(/padding length/);

    const unencrypted = encodeIkeMessage({
      initiatorSpi: inputs.initiatorSpi,
      responderSpi: inputs.responderSpi,
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_INITIATOR,
      messageId: 2,
      payloads: [],
    });
    await expect(
      openIkeEncryptedMessage(unencrypted, handshake.keys.skEi),
    ).rejects.toThrow(/outer payload is SK/);

    const headerOnlySk = encodeIkeHeader({
      initiatorSpi: inputs.initiatorSpi,
      responderSpi: inputs.responderSpi,
      nextPayload: PayloadType.SK,
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_INITIATOR,
      messageId: 2,
      length: IKE_HEADER_BYTES,
    });
    await expect(
      openIkeEncryptedMessage(headerOnlySk, handshake.keys.skEi),
    ).rejects.toThrow(/too short/);

    const sealed = await sealIkeEncryptedMessage({
      ...sealingOptions,
      innerPayloads: [payload(PayloadType.NOTIFY, utf8("status"))],
    });
    const wrongSkLength = sealed.message.slice();
    wrongSkLength[IKE_HEADER_BYTES + 3] ^= 1;
    await expect(
      openIkeEncryptedMessage(wrongSkLength, handshake.keys.skEi),
    ).rejects.toThrow(/SK payload length/);
  });
});
