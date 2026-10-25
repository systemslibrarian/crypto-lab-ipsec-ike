import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bytesToHex, concatBytes, hexToBytes, utf8 } from "./bytes";
import {
  buildSignedOctets,
  computePskAuth,
  deriveIkeKeys,
  deriveInitialChildKeys,
  negotiateMode,
  openIkeEncryptedMessage,
  prfPlus,
  runIkeHandshake,
  sealIkeEncryptedMessage,
  verifyReceivedIkeAuth,
  verifyPskAuth,
  type HandshakeInputs,
} from "./ike";
import {
  ExchangeType,
  IKE_FLAG_INITIATOR,
  PayloadType,
  decodePayloadChain,
  encodeIdBody,
  encodeTsBody,
  parseIkeHeader,
  payload,
} from "./ike-wire";
import { addressRange, anyPort, portRange } from "./spd";
import { aesGcmSeal } from "./primitives";

const fixture = (): HandshakeInputs => ({
  initiatorPrivate: hexToBytes(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  ),
  responderPrivate: hexToBytes(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  ),
  nonceI: hexToBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  ),
  nonceR: hexToBytes(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  ),
  initiatorSpi: hexToBytes("0102030405060708"),
  responderSpi: hexToBytes("1112131415161718"),
  initiatorInboundChildSpi: hexToBytes("a1a2a3a4"),
  responderInboundChildSpi: hexToBytes("b1b2b3b4"),
  initiatorIkeIv: hexToBytes("0000000000000001"),
  responderIkeIv: hexToBytes("0000000000000002"),
  psk: utf8("correct horse battery staple for IKEv2"),
  initiatorIdentity: {
    type: 2,
    data: utf8("initiator.example"),
    label: "initiator.example",
  },
  responderIdentity: {
    type: 2,
    data: utf8("responder.example"),
    label: "responder.example",
  },
  offeredSelector: {
    sourceAddress: addressRange("192.0.2.0", "192.0.2.255"),
    destinationAddress: addressRange("198.51.100.0", "198.51.100.255"),
    sourcePort: anyPort(),
    destinationPort: portRange(1, 1024),
    protocol: 0,
  },
  responderPolicy: {
    sourceAddress: addressRange("192.0.2.10", "192.0.2.40"),
    destinationAddress: addressRange("198.51.100.16", "198.51.100.31"),
    sourcePort: anyPort(),
    destinationPort: portRange(22),
    protocol: 6,
  },
  requestedMode: "transport",
  responderAllowsTransport: true,
  initiatorAcceptsTunnelFallback: false,
  rejectAllZeroDh: true,
});

function nodeHmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return Uint8Array.from(createHmac("sha256", key).update(data).digest());
}

function independentPrfPlus(
  key: Uint8Array,
  seed: Uint8Array,
  length: number,
): Uint8Array {
  const blocks: Uint8Array[] = [];
  let previous: Uint8Array = new Uint8Array();
  for (let counter = 1; blocks.length * 32 < length; counter += 1) {
    previous = nodeHmac(
      key,
      concatBytes(previous, seed, Uint8Array.of(counter)),
    );
    blocks.push(previous);
  }
  return concatBytes(...blocks).slice(0, length);
}

describe("IKEv2 PRF and key schedule", () => {
  it("matches an independent HMAC prf+ reference across block boundaries", async () => {
    const key = hexToBytes("00112233445566778899aabbccddeeff");
    const seed = utf8("Ni | Nr | SPIi | SPIr");
    expect(await prfPlus(key, seed, 100)).toEqual(
      independentPrfPlus(key, seed, 100),
    );
    expect(await prfPlus(key, seed, 0)).toEqual(new Uint8Array());
    await expect(prfPlus(key, seed, 32 * 256)).rejects.toThrow(/255/);
  });

  it("derives SKEYSEED and the AEAD-only split independently", async () => {
    const run = fixture();
    const shared = hexToBytes(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    );
    const keys = await deriveIkeKeys({
      nonceI: run.nonceI,
      nonceR: run.nonceR,
      sharedSecret: shared,
      initiatorSpi: run.initiatorSpi,
      responderSpi: run.responderSpi,
    });
    const nonces = concatBytes(run.nonceI, run.nonceR);
    const expectedSkeyseed = nodeHmac(nonces, shared);
    const expectedKeymat = independentPrfPlus(
      expectedSkeyseed,
      concatBytes(nonces, run.initiatorSpi, run.responderSpi),
      136,
    );
    expect(keys.skeyseed).toEqual(expectedSkeyseed);
    expect(keys.skD).toEqual(expectedKeymat.slice(0, 32));
    expect(keys.skAi).toHaveLength(0);
    expect(keys.skAr).toHaveLength(0);
    expect(keys.skEi).toEqual(expectedKeymat.slice(32, 52));
    expect(keys.skEr).toEqual(expectedKeymat.slice(52, 72));
    expect(keys.skPi).toEqual(expectedKeymat.slice(72, 104));
    expect(keys.skPr).toEqual(expectedKeymat.slice(104, 136));
  });

  it("derives initial Child KEYMAT from SK_d and Ni|Nr only, in directional order", async () => {
    const run = fixture();
    const skD = new Uint8Array(32).map((_, index) => index);
    const child = await deriveInitialChildKeys(skD, run.nonceI, run.nonceR);
    const expected = independentPrfPlus(
      skD,
      concatBytes(run.nonceI, run.nonceR),
      40,
    );
    expect(child.initiatorToResponder).toEqual(expected.slice(0, 20));
    expect(child.responderToInitiator).toEqual(expected.slice(20));
    const wronglyRepeatedDh = independentPrfPlus(
      skD,
      concatBytes(run.nonceI, run.nonceR, new Uint8Array(32).fill(7)),
      40,
    );
    expect(
      concatBytes(child.initiatorToResponder, child.responderToInitiator),
    ).not.toEqual(wronglyRepeatedDh);
  });
});

describe("four-message PSK IKEv2 teaching profile", () => {
  it("builds IKE_SA_INIT then encrypted IKE_AUTH with the first Child SA inside", async () => {
    const result = await runIkeHandshake(fixture());
    const requestHeader = parseIkeHeader(result.ikeSaInitRequest);
    const responseHeader = parseIkeHeader(result.ikeSaInitResponse);
    expect(requestHeader.exchangeType).toBe(ExchangeType.IKE_SA_INIT);
    expect(responseHeader.exchangeType).toBe(ExchangeType.IKE_SA_INIT);
    expect(requestHeader.messageId).toBe(0);
    expect(responseHeader.messageId).toBe(0);
    expect(requestHeader.responderSpi).toEqual(new Uint8Array(8));

    const requestInitPayloads = decodePayloadChain(
      result.ikeSaInitRequest.slice(28),
      requestHeader.nextPayload,
    );
    expect(requestInitPayloads.map(({ type }) => type)).toEqual([
      PayloadType.SA,
      PayloadType.KE,
      PayloadType.NONCE,
    ]);

    expect(result.openedRequest.header.exchangeType).toBe(
      ExchangeType.IKE_AUTH,
    );
    expect(result.openedRequest.header.messageId).toBe(1);
    expect(result.openedRequest.payloads.map(({ type }) => type)).toEqual([
      PayloadType.IDI,
      PayloadType.AUTH,
      PayloadType.SA,
      PayloadType.TSI,
      PayloadType.TSR,
      PayloadType.NOTIFY,
    ]);
    expect(
      result.openedRequest.payloads.some(({ type }) => type === PayloadType.KE),
    ).toBe(false);
    expect(result.openedRequest.payloads[3]!.body).toEqual(
      encodeTsBody(fixture().offeredSelector, "source"),
    );
    expect(result.openedRequest.payloads[4]!.body).toEqual(
      encodeTsBody(fixture().offeredSelector, "destination"),
    );
    expect(result.openedResponse.payloads.map(({ type }) => type)).toEqual([
      PayloadType.IDR,
      PayloadType.AUTH,
      PayloadType.SA,
      PayloadType.TSI,
      PayloadType.TSR,
      PayloadType.NOTIFY,
    ]);
    expect(result.openedResponse.payloads[3]!.body).toEqual(
      encodeTsBody(result.narrowedSelector, "source"),
    );
    expect(result.openedResponse.payloads[4]!.body).toEqual(
      encodeTsBody(result.narrowedSelector, "destination"),
    );
    expect(result.mode.establishedMode).toBe("transport");
    expect(result.mode.responderEchoedTransport).toBe(true);
  });

  it("binds each AUTH value to the first message, peer nonce, and exact ID body", async () => {
    const inputs = fixture();
    const result = await runIkeHandshake(inputs);
    expect(result.initiatorAuthVerification).toMatchObject({
      accepted: true,
      identityMatched: true,
      authenticationMatched: true,
    });
    expect(
      await verifyPskAuth(
        inputs.psk,
        result.initiatorSignedOctets,
        result.initiatorAuth,
      ),
    ).toBe(true);
    const transmittedAuth = result.openedRequest.payloads[1]!.body.slice(4);
    expect(transmittedAuth).toEqual(result.initiatorAuth);
    const changedAuth = transmittedAuth.slice();
    changedAuth[0] = changedAuth[0]! ^ 1;
    expect(
      await verifyPskAuth(
        inputs.psk,
        result.initiatorSignedOctets,
        changedAuth,
      ),
    ).toBe(false);

    const changedMessage = result.ikeSaInitRequest.slice();
    changedMessage[40] ^= 1;
    const wrongTranscript = await buildSignedOctets({
      firstMessage: changedMessage,
      peerNonce: inputs.nonceR,
      skP: result.keys.skPi,
      idPayloadBody: encodeIdBody(
        inputs.initiatorIdentity.type,
        inputs.initiatorIdentity.data,
      ),
    });
    expect(
      await verifyPskAuth(inputs.psk, wrongTranscript, result.initiatorAuth),
    ).toBe(false);

    const wrongIdentity = await buildSignedOctets({
      firstMessage: result.ikeSaInitRequest,
      peerNonce: inputs.nonceR,
      skP: result.keys.skPi,
      idPayloadBody: encodeIdBody(2, utf8("attacker.example")),
    });
    expect(
      await verifyPskAuth(inputs.psk, wrongIdentity, result.initiatorAuth),
    ).toBe(false);
    expect(
      await verifyPskAuth(
        utf8("different shared key material"),
        result.initiatorSignedOctets,
        result.initiatorAuth,
      ),
    ).toBe(false);

    const receiverInputs = {
      opened: result.openedRequest,
      sender: "initiator" as const,
      expectedIdentity: inputs.initiatorIdentity,
      expectedInitiatorSpi: inputs.initiatorSpi,
      expectedResponderSpi: inputs.responderSpi,
      firstMessage: result.ikeSaInitRequest,
      peerNonce: inputs.nonceR,
      skP: result.keys.skPi,
      psk: inputs.psk,
    };
    expect(
      await verifyReceivedIkeAuth({
        ...receiverInputs,
        firstMessage: changedMessage,
      }),
    ).toMatchObject({ accepted: false, authenticationMatched: false });
    expect(
      await verifyReceivedIkeAuth({
        ...receiverInputs,
        expectedIdentity: {
          type: 2,
          data: utf8("attacker.example"),
          label: "attacker.example",
        },
      }),
    ).toMatchObject({ accepted: false, identityMatched: false });
    const changedOpened = {
      ...result.openedRequest,
      payloads: result.openedRequest.payloads.map((item) => ({
        ...item,
        body: item.body.slice(),
        encoded: item.encoded.slice(),
      })),
    };
    changedOpened.payloads[1]!.body[4] ^= 1;
    expect(
      await verifyReceivedIkeAuth({ ...receiverInputs, opened: changedOpened }),
    ).toMatchObject({ accepted: false, authenticationMatched: false });
    expect(
      await verifyReceivedIkeAuth({
        ...receiverInputs,
        opened: {
          ...result.openedRequest,
          header: { ...result.openedRequest.header, messageId: 2 },
        },
      }),
    ).toMatchObject({
      accepted: false,
      headerMatched: false,
      identityMatched: true,
      authenticationMatched: true,
    });
  });

  it("authenticates the IKE header plus SK header as AAD", async () => {
    const result = await runIkeHandshake(fixture());
    expect(result.ikeAuthRequest.aad).toEqual(
      result.ikeAuthRequest.message.slice(0, 32),
    );
    const changedHeader = result.ikeAuthRequest.message.slice();
    changedHeader[19] ^= 0x20;
    await expect(
      openIkeEncryptedMessage(changedHeader, result.keys.skEi),
    ).rejects.toThrow(/authentication/);
    const changedCiphertext = result.ikeAuthRequest.message.slice();
    changedCiphertext[45] ^= 1;
    await expect(
      openIkeEncryptedMessage(changedCiphertext, result.keys.skEi),
    ).rejects.toThrow(/authentication/);
  });

  it("refuses malformed authenticated padding after a deliberately resealed fixture", async () => {
    const inputs = fixture();
    const result = await runIkeHandshake(inputs);
    const sealed = await sealIkeEncryptedMessage({
      initiatorSpi: inputs.initiatorSpi,
      responderSpi: inputs.responderSpi,
      flags: IKE_FLAG_INITIATOR,
      messageId: 1,
      keyWithSalt: result.keys.skEi,
      explicitIv: hexToBytes("0000000000000003"),
      innerPayloads: [
        payload(PayloadType.IDI, encodeIdBody(2, utf8("i.example"))),
      ],
      paddingLength: 2,
    });
    const malformedPlaintext = sealed.plaintext.slice();
    malformedPlaintext[malformedPlaintext.length - 3] = 9;
    malformedPlaintext[malformedPlaintext.length - 2] = 9;
    const malformed = await aesGcmSeal(
      result.keys.skEi.slice(0, 16),
      sealed.nonce,
      malformedPlaintext,
      sealed.aad,
    );
    const malformedMessage = concatBytes(
      sealed.aad,
      sealed.explicitIv,
      malformed.ciphertext,
      malformed.tag,
    );
    await expect(
      openIkeEncryptedMessage(malformedMessage, result.keys.skEi),
    ).rejects.toThrow(/padding/);
  });

  it("fails when no Child-SA selector subset is authorized", async () => {
    const inputs = fixture();
    inputs.responderPolicy = {
      ...inputs.responderPolicy,
      destinationAddress: addressRange("203.0.113.1"),
    };
    await expect(runIkeHandshake(inputs)).rejects.toThrow(
      /no acceptable traffic-selector/i,
    );
  });

  it("refuses zero IKE SPIs and reserved Child-SA SPI values before encoding", async () => {
    const zeroIke = fixture();
    zeroIke.initiatorSpi = new Uint8Array(8);
    await expect(runIkeHandshake(zeroIke)).rejects.toThrow(
      /IKE SPIs must be nonzero/,
    );

    const reservedChild = fixture();
    reservedChild.responderInboundChildSpi = hexToBytes("000000ff");
    await expect(runIkeHandshake(reservedChild)).rejects.toThrow(
      /greater than 255/,
    );
  });

  it("uses deterministic fixtures only through explicit inputs", async () => {
    const first = await runIkeHandshake(fixture());
    const second = await runIkeHandshake(fixture());
    expect(bytesToHex(first.ikeAuthRequest.message)).toBe(
      bytesToHex(second.ikeAuthRequest.message),
    );
    expect(bytesToHex(first.ikeAuthResponse.message)).toBe(
      bytesToHex(second.ikeAuthResponse.message),
    );
  });
});

describe("transport-mode request and fallback", () => {
  it("calls transport established only after an echo", () => {
    expect(
      negotiateMode({
        requested: "transport",
        responderAllowsTransport: true,
        initiatorAcceptsTunnelFallback: false,
      }),
    ).toMatchObject({
      responderEchoedTransport: true,
      establishedMode: "transport",
      childState: "established",
    });
  });

  it("falls back to tunnel or deletes according to initiator policy", () => {
    expect(
      negotiateMode({
        requested: "transport",
        responderAllowsTransport: false,
        initiatorAcceptsTunnelFallback: true,
      }),
    ).toMatchObject({ establishedMode: "tunnel", childState: "established" });
    expect(
      negotiateMode({
        requested: "transport",
        responderAllowsTransport: false,
        initiatorAcceptsTunnelFallback: false,
      }),
    ).toMatchObject({
      establishedMode: "tunnel",
      childState: "delete-required",
    });
  });

  it("treats an unnotified tunnel request as tunnel mode", () => {
    expect(
      negotiateMode({
        requested: "tunnel",
        responderAllowsTransport: true,
        initiatorAcceptsTunnelFallback: false,
      }),
    ).toMatchObject({
      responderEchoedTransport: false,
      establishedMode: "tunnel",
    });
  });
});

describe("AUTH construction input validation", () => {
  it("rejects a too-short PSK and incomplete first message", async () => {
    await expect(
      computePskAuth(utf8("short"), new Uint8Array(80)),
    ).rejects.toThrow(/at least 16/);
    await expect(
      buildSignedOctets({
        firstMessage: new Uint8Array(20),
        peerNonce: new Uint8Array(32),
        skP: new Uint8Array(32),
        idPayloadBody: encodeIdBody(2, utf8("i.example")),
      }),
    ).rejects.toThrow(/complete/);
  });
});
