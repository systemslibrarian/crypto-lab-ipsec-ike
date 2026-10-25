import {
  bytesToHex,
  bytesEqual,
  concatBytes,
  randomBytes,
  readU32be,
  readU64be,
  requireLength,
  u16be,
  u64be,
  utf8,
} from "./bytes";
import {
  ExchangeType,
  IKE_FLAG_INITIATOR,
  IKE_FLAG_RESPONSE,
  IKE_HEADER_BYTES,
  PayloadType,
  USE_TRANSPORT_MODE,
  childSaProposal,
  decodePayloadChain,
  encodeAuthBody,
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
  type IkePayload,
  type ParsedPayload,
} from "./ike-wire";
import { aesGcmOpen, aesGcmSeal, hmacSha256 } from "./primitives";
import { intersectTrafficSelectors, type TrafficSelector } from "./spd";
import { x25519PublicKey, x25519WithPolicy, type X25519Result } from "./x25519";

const PRF_OUTPUT_BYTES = 32;
const AES_GCM_KEY_BYTES = 16;
const AES_GCM_SALT_BYTES = 4;
const IKE_ENCRYPTION_KEYMAT_BYTES = AES_GCM_KEY_BYTES + AES_GCM_SALT_BYTES;
const IKE_KEYMAT_BYTES =
  PRF_OUTPUT_BYTES + IKE_ENCRYPTION_KEYMAT_BYTES * 2 + PRF_OUTPUT_BYTES * 2;
const AUTH_METHOD_SHARED_KEY_MIC = 2;
const KEY_PAD = utf8("Key Pad for IKEv2");

export interface IkeKeys {
  skeyseed: Uint8Array;
  skD: Uint8Array;
  /** Empty for an AEAD-only IKE proposal. */
  skAi: Uint8Array;
  /** Empty for an AEAD-only IKE proposal. */
  skAr: Uint8Array;
  /** AES-128 key followed by the four-octet IKE salt. */
  skEi: Uint8Array;
  /** AES-128 key followed by the four-octet IKE salt. */
  skEr: Uint8Array;
  skPi: Uint8Array;
  skPr: Uint8Array;
}

export interface ChildKeys {
  /** First KEYMAT bytes: initiator outbound, responder inbound. */
  initiatorToResponder: Uint8Array;
  /** Second KEYMAT bytes: responder outbound, initiator inbound. */
  responderToInitiator: Uint8Array;
}

export interface SealedIkeMessage {
  message: Uint8Array;
  aad: Uint8Array;
  nonce: Uint8Array;
  explicitIv: Uint8Array;
  plaintext: Uint8Array;
  padding: Uint8Array;
  padLength: number;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  firstInnerPayload: number;
}

export interface OpenedIkeMessage {
  header: ReturnType<typeof parseIkeHeader>;
  aad: Uint8Array;
  nonce: Uint8Array;
  explicitIv: Uint8Array;
  plaintext: Uint8Array;
  padding: Uint8Array;
  padLength: number;
  payloads: ParsedPayload[];
}

export type IpsecMode = "transport" | "tunnel";
export type ChildSaState = "established" | "delete-required";

export interface ModeNegotiation {
  requested: IpsecMode;
  responderEchoedTransport: boolean;
  establishedMode: IpsecMode;
  childState: ChildSaState;
  reason: string;
}

export interface HandshakeInputs {
  initiatorPrivate: Uint8Array;
  responderPrivate: Uint8Array;
  nonceI: Uint8Array;
  nonceR: Uint8Array;
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
  initiatorInboundChildSpi: Uint8Array;
  responderInboundChildSpi: Uint8Array;
  initiatorIkeIv: Uint8Array;
  responderIkeIv: Uint8Array;
  psk: Uint8Array;
  initiatorIdentity: IkeIdentity;
  responderIdentity: IkeIdentity;
  offeredSelector: TrafficSelector;
  responderPolicy: TrafficSelector;
  requestedMode: IpsecMode;
  responderAllowsTransport: boolean;
  initiatorAcceptsTunnelFallback: boolean;
  rejectAllZeroDh?: boolean;
}

export interface IkeIdentity {
  /** IKEv2 Identification Type, such as 1 (IPv4) or 2 (FQDN). */
  type: number;
  data: Uint8Array;
  label: string;
}

export interface HandshakeResult {
  initiatorPublic: Uint8Array;
  responderPublic: Uint8Array;
  initiatorDh: X25519Result;
  responderDh: X25519Result;
  ikeSaInitRequest: Uint8Array;
  ikeSaInitResponse: Uint8Array;
  keys: IkeKeys;
  initiatorSignedOctets: Uint8Array;
  responderSignedOctets: Uint8Array;
  initiatorAuth: Uint8Array;
  responderAuth: Uint8Array;
  initiatorAuthVerification: IkeAuthVerification;
  responderAuthVerification: IkeAuthVerification;
  ikeAuthRequest: SealedIkeMessage;
  ikeAuthResponse: SealedIkeMessage;
  openedRequest: OpenedIkeMessage;
  openedResponse: OpenedIkeMessage;
  childKeys: ChildKeys;
  narrowedSelector: TrafficSelector;
  mode: ModeNegotiation;
  /** Continues the original initiator's SK_ei explicit-IV allocation. */
  initiatorIkeSender: IkeMessageSender;
  /** Continues the original responder's SK_er explicit-IV allocation. */
  responderIkeSender: IkeMessageSender;
}

export interface IkeAuthVerification {
  accepted: boolean;
  headerMatched: boolean;
  identityMatched: boolean;
  authenticationMatched: boolean;
  reason: string;
}

export async function prfPlus(
  key: Uint8Array,
  seed: Uint8Array,
  outputLength: number,
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(outputLength) || outputLength < 0) {
    throw new RangeError(
      "prf+ output length must be a non-negative safe integer.",
    );
  }
  if (outputLength === 0) return new Uint8Array();
  const blocks = Math.ceil(outputLength / PRF_OUTPUT_BYTES);
  if (blocks > 255)
    throw new RangeError("prf+ cannot emit more than 255 PRF blocks.");
  const output: Uint8Array[] = [];
  let previous = new Uint8Array();
  for (let counter = 1; counter <= blocks; counter += 1) {
    previous = await hmacSha256(
      key,
      concatBytes(previous, seed, Uint8Array.of(counter)),
    );
    output.push(previous);
  }
  return concatBytes(...output).slice(0, outputLength);
}

export async function deriveIkeKeys(options: {
  nonceI: Uint8Array;
  nonceR: Uint8Array;
  sharedSecret: Uint8Array;
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
}): Promise<IkeKeys> {
  validateNonce(options.nonceI, "initiator nonce");
  validateNonce(options.nonceR, "responder nonce");
  requireLength(options.sharedSecret, 32, "X25519 shared secret");
  requireLength(options.initiatorSpi, 8, "IKE initiator SPI");
  requireLength(options.responderSpi, 8, "IKE responder SPI");
  const nonces = concatBytes(options.nonceI, options.nonceR);
  const skeyseed = await hmacSha256(nonces, options.sharedSecret);
  const keymat = await prfPlus(
    skeyseed,
    concatBytes(nonces, options.initiatorSpi, options.responderSpi),
    IKE_KEYMAT_BYTES,
  );
  let offset = 0;
  const take = (length: number): Uint8Array => {
    const part = keymat.slice(offset, offset + length);
    offset += length;
    return part;
  };
  const result: IkeKeys = {
    skeyseed,
    skD: take(PRF_OUTPUT_BYTES),
    skAi: new Uint8Array(),
    skAr: new Uint8Array(),
    skEi: take(IKE_ENCRYPTION_KEYMAT_BYTES),
    skEr: take(IKE_ENCRYPTION_KEYMAT_BYTES),
    skPi: take(PRF_OUTPUT_BYTES),
    skPr: take(PRF_OUTPUT_BYTES),
  };
  if (offset !== keymat.length)
    throw new Error("Internal IKE key split did not consume KEYMAT.");
  return result;
}

export async function deriveInitialChildKeys(
  skD: Uint8Array,
  nonceI: Uint8Array,
  nonceR: Uint8Array,
): Promise<ChildKeys> {
  requireLength(skD, PRF_OUTPUT_BYTES, "SK_d");
  validateNonce(nonceI, "initiator nonce");
  validateNonce(nonceR, "responder nonce");
  const keymat = await prfPlus(
    skD,
    concatBytes(nonceI, nonceR),
    IKE_ENCRYPTION_KEYMAT_BYTES * 2,
  );
  return {
    initiatorToResponder: keymat.slice(0, IKE_ENCRYPTION_KEYMAT_BYTES),
    responderToInitiator: keymat.slice(IKE_ENCRYPTION_KEYMAT_BYTES),
  };
}

export async function buildSignedOctets(options: {
  firstMessage: Uint8Array;
  peerNonce: Uint8Array;
  skP: Uint8Array;
  idPayloadBody: Uint8Array;
}): Promise<Uint8Array> {
  validateNonce(options.peerNonce, "peer nonce");
  requireLength(options.skP, PRF_OUTPUT_BYTES, "SK_p");
  if (options.firstMessage.length < IKE_HEADER_BYTES) {
    throw new Error(
      "Signed octets require a complete first IKE_SA_INIT message.",
    );
  }
  const macedId = await hmacSha256(options.skP, options.idPayloadBody);
  return concatBytes(options.firstMessage, options.peerNonce, macedId);
}

export async function computePskAuth(
  psk: Uint8Array,
  signedOctets: Uint8Array,
): Promise<Uint8Array> {
  if (psk.length < 16)
    throw new RangeError(
      "The bounded lesson requires a PSK of at least 16 octets.",
    );
  const secret = await hmacSha256(psk, KEY_PAD);
  return hmacSha256(secret, signedOctets);
}

export async function verifyPskAuth(
  psk: Uint8Array,
  signedOctets: Uint8Array,
  authenticationData: Uint8Array,
): Promise<boolean> {
  return bytesEqual(
    await computePskAuth(psk, signedOctets),
    authenticationData,
  );
}

export async function verifyReceivedIkeAuth(options: {
  opened: OpenedIkeMessage;
  sender: "initiator" | "responder";
  expectedIdentity: IkeIdentity;
  expectedInitiatorSpi: Uint8Array;
  expectedResponderSpi: Uint8Array;
  firstMessage: Uint8Array;
  peerNonce: Uint8Array;
  skP: Uint8Array;
  psk: Uint8Array;
}): Promise<IkeAuthVerification> {
  requireLength(options.expectedInitiatorSpi, 8, "expected IKE initiator SPI");
  requireLength(options.expectedResponderSpi, 8, "expected IKE responder SPI");
  const expectedFlags =
    options.sender === "initiator" ? IKE_FLAG_INITIATOR : IKE_FLAG_RESPONSE;
  const headerMatched =
    options.opened.header.exchangeType === ExchangeType.IKE_AUTH &&
    options.opened.header.messageId === 1 &&
    options.opened.header.flags === expectedFlags &&
    bytesEqual(
      options.opened.header.initiatorSpi,
      options.expectedInitiatorSpi,
    ) &&
    bytesEqual(
      options.opened.header.responderSpi,
      options.expectedResponderSpi,
    );
  const expectedIdType =
    options.sender === "initiator" ? PayloadType.IDI : PayloadType.IDR;
  const idPayload = options.opened.payloads[0];
  const authPayload = options.opened.payloads[1];
  if (
    idPayload?.type !== expectedIdType ||
    authPayload?.type !== PayloadType.AUTH
  ) {
    return {
      accepted: false,
      headerMatched,
      identityMatched: false,
      authenticationMatched: false,
      reason:
        "The protected message does not begin with the required ID and AUTH payloads.",
    };
  }
  if (
    idPayload.body.length < 5 ||
    idPayload.body.slice(1, 4).some((byte) => byte !== 0)
  ) {
    return {
      accepted: false,
      headerMatched,
      identityMatched: false,
      authenticationMatched: false,
      reason: "The protected identity body is malformed.",
    };
  }
  const identityMatched =
    idPayload.body[0] === options.expectedIdentity.type &&
    bytesEqual(idPayload.body.slice(4), options.expectedIdentity.data);
  if (
    authPayload.body.length !== 36 ||
    authPayload.body[0] !== AUTH_METHOD_SHARED_KEY_MIC ||
    authPayload.body.slice(1, 4).some((byte) => byte !== 0)
  ) {
    return {
      accepted: false,
      headerMatched,
      identityMatched,
      authenticationMatched: false,
      reason: "The AUTH payload is not a method-2 HMAC-SHA-256 value.",
    };
  }
  const signedOctets = await buildSignedOctets({
    firstMessage: options.firstMessage,
    peerNonce: options.peerNonce,
    skP: options.skP,
    idPayloadBody: idPayload.body,
  });
  const authenticationMatched = await verifyPskAuth(
    options.psk,
    signedOctets,
    authPayload.body.slice(4),
  );
  return {
    accepted: headerMatched && identityMatched && authenticationMatched,
    headerMatched,
    identityMatched,
    authenticationMatched,
    reason:
      headerMatched && identityMatched && authenticationMatched
        ? "The expected IKE_AUTH header, identity and PSK AUTH verified against the received transcript."
        : !headerMatched
          ? "The received message is not the expected IKE_AUTH exchange on this IKE SA."
          : !identityMatched
            ? "The received identity does not match the peer selected by policy."
            : "The received AUTH value does not verify against the exact transcript and identity.",
  };
}

export async function sealIkeEncryptedMessage(options: {
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
  flags: number;
  messageId: number;
  exchangeType?: number;
  keyWithSalt: Uint8Array;
  explicitIv: Uint8Array;
  innerPayloads: readonly IkePayload[];
  /** Optional teaching-profile padding; AEAD itself requires no block alignment. */
  paddingLength?: number;
}): Promise<SealedIkeMessage> {
  requireLength(
    options.keyWithSalt,
    IKE_ENCRYPTION_KEYMAT_BYTES,
    "IKE encryption key material",
  );
  requireLength(options.explicitIv, 8, "IKE explicit IV");
  if (options.innerPayloads.length === 0)
    throw new Error("IKE encrypted payload cannot be empty.");
  const inner = encodePayloadChain(options.innerPayloads);
  const padLength = options.paddingLength ?? 0;
  if (!Number.isInteger(padLength) || padLength < 0 || padLength > 255) {
    throw new RangeError("IKE padding length must be an octet.");
  }
  const padding = Uint8Array.from(
    { length: padLength },
    (_, index) => index + 1,
  );
  const plaintext = concatBytes(inner.bytes, padding, Uint8Array.of(padLength));
  const skPayloadLength = 4 + 8 + plaintext.length + 16;
  const messageLength = IKE_HEADER_BYTES + skPayloadLength;
  const header = encodeIkeHeader({
    initiatorSpi: options.initiatorSpi,
    responderSpi: options.responderSpi,
    nextPayload: PayloadType.SK,
    exchangeType: options.exchangeType ?? ExchangeType.IKE_AUTH,
    flags: options.flags,
    messageId: options.messageId,
    length: messageLength,
  });
  const skHeader = concatBytes(
    Uint8Array.of(inner.firstPayload, 0),
    u16be(skPayloadLength),
  );
  const wirePrefix = concatBytes(header, skHeader);
  const aad = ikeAad(wirePrefix);
  const key = options.keyWithSalt.slice(0, AES_GCM_KEY_BYTES);
  const salt = options.keyWithSalt.slice(AES_GCM_KEY_BYTES);
  const nonce = concatBytes(salt, options.explicitIv);
  const sealed = await aesGcmSeal(key, nonce, plaintext, aad);
  return {
    message: concatBytes(
      wirePrefix,
      options.explicitIv,
      sealed.ciphertext,
      sealed.tag,
    ),
    aad,
    nonce,
    explicitIv: options.explicitIv.slice(),
    plaintext,
    padding,
    padLength,
    ciphertext: sealed.ciphertext,
    tag: sealed.tag,
    firstInnerPayload: inner.firstPayload,
  };
}

export async function openIkeEncryptedMessage(
  message: Uint8Array,
  keyWithSalt: Uint8Array,
): Promise<OpenedIkeMessage> {
  requireLength(
    keyWithSalt,
    IKE_ENCRYPTION_KEYMAT_BYTES,
    "IKE encryption key material",
  );
  const header = parseIkeHeader(message);
  if (header.nextPayload !== PayloadType.SK) {
    throw new Error(
      "Expected an encrypted IKEv2 message whose outer payload is SK.",
    );
  }
  if (message.length < IKE_HEADER_BYTES + 4 + 8 + 16 + 1) {
    throw new Error("Encrypted IKE message is too short.");
  }
  const skOffset = IKE_HEADER_BYTES;
  const firstInnerPayload = message[skOffset]!;
  const skPayloadLength =
    (message[skOffset + 2]! << 8) | message[skOffset + 3]!;
  if (skPayloadLength !== message.length - IKE_HEADER_BYTES) {
    throw new Error("SK payload length does not match the IKE message.");
  }
  const aad = ikeAad(message);
  const explicitIv = message.slice(IKE_HEADER_BYTES + 4, IKE_HEADER_BYTES + 12);
  const ciphertext = message.slice(IKE_HEADER_BYTES + 12, -16);
  const tag = message.slice(-16);
  const key = keyWithSalt.slice(0, AES_GCM_KEY_BYTES);
  const salt = keyWithSalt.slice(AES_GCM_KEY_BYTES);
  const nonce = concatBytes(salt, explicitIv);
  const plaintext = await aesGcmOpen(key, nonce, ciphertext, tag, aad);
  if (plaintext.length === 0)
    throw new Error("Encrypted IKE plaintext is empty.");
  const padLength = plaintext.at(-1)!;
  if (padLength + 1 > plaintext.length)
    throw new Error("IKE padding length is invalid.");
  const paddingStart = plaintext.length - 1 - padLength;
  const padding = plaintext.slice(paddingStart, -1);
  const expectedPadding = Uint8Array.from(
    { length: padLength },
    (_, index) => index + 1,
  );
  if (!bytesEqual(padding, expectedPadding))
    throw new Error("IKE teaching-profile padding is invalid.");
  const innerBytes = plaintext.slice(0, paddingStart);
  return {
    header,
    aad,
    nonce,
    explicitIv,
    plaintext,
    padding,
    padLength,
    payloads: decodePayloadChain(innerBytes, firstInnerPayload),
  };
}

/** RFC 7296 authenticates the complete IKE header and generic SK header. */
function ikeAad(message: Uint8Array): Uint8Array {
  return message.slice(0, IKE_HEADER_BYTES + 4);
}

export function negotiateMode(options: {
  requested: IpsecMode;
  responderAllowsTransport: boolean;
  initiatorAcceptsTunnelFallback: boolean;
}): ModeNegotiation {
  if (options.requested === "tunnel") {
    return {
      requested: "tunnel",
      responderEchoedTransport: false,
      establishedMode: "tunnel",
      childState: "established",
      reason:
        "Tunnel mode was requested and is the default when no transport notification is used.",
    };
  }
  if (options.responderAllowsTransport) {
    return {
      requested: "transport",
      responderEchoedTransport: true,
      establishedMode: "transport",
      childState: "established",
      reason:
        "The responder echoed USE_TRANSPORT_MODE, so transport mode is established.",
    };
  }
  return {
    requested: "transport",
    responderEchoedTransport: false,
    establishedMode: "tunnel",
    childState: options.initiatorAcceptsTunnelFallback
      ? "established"
      : "delete-required",
    reason: options.initiatorAcceptsTunnelFallback
      ? "No echo means tunnel fallback; local policy accepted that fallback."
      : "No echo means tunnel fallback; local transport-only policy requires a protected Child-SA Delete.",
  };
}

export async function runIkeHandshake(
  inputs: HandshakeInputs,
): Promise<HandshakeResult> {
  validateHandshakeInputs(inputs);
  const initiatorPublic = x25519PublicKey(inputs.initiatorPrivate);
  const responderPublic = x25519PublicKey(inputs.responderPrivate);
  const initiatorDh = x25519WithPolicy(
    inputs.initiatorPrivate,
    responderPublic,
    {
      rejectAllZero: inputs.rejectAllZeroDh,
    },
  );
  const responderDh = x25519WithPolicy(
    inputs.responderPrivate,
    initiatorPublic,
    {
      rejectAllZero: inputs.rejectAllZeroDh,
    },
  );
  if (!bytesEqual(initiatorDh.sharedSecret, responderDh.sharedSecret)) {
    throw new Error("IKE peers derived different X25519 shared secrets.");
  }

  const ikeSaInitRequest = buildIkeSaInit({
    initiatorSpi: inputs.initiatorSpi,
    responderSpi: new Uint8Array(8),
    flags: IKE_FLAG_INITIATOR,
    publicKey: initiatorPublic,
    nonce: inputs.nonceI,
  });
  const ikeSaInitResponse = buildIkeSaInit({
    initiatorSpi: inputs.initiatorSpi,
    responderSpi: inputs.responderSpi,
    flags: IKE_FLAG_RESPONSE,
    publicKey: responderPublic,
    nonce: inputs.nonceR,
  });
  const keys = await deriveIkeKeys({
    nonceI: inputs.nonceI,
    nonceR: inputs.nonceR,
    sharedSecret: initiatorDh.sharedSecret,
    initiatorSpi: inputs.initiatorSpi,
    responderSpi: inputs.responderSpi,
  });

  const narrowedSelector = intersectTrafficSelectors(
    inputs.offeredSelector,
    inputs.responderPolicy,
  );
  if (!narrowedSelector)
    throw new Error(
      "Responder policy found no acceptable traffic-selector subset.",
    );
  const mode = negotiateMode({
    requested: inputs.requestedMode,
    responderAllowsTransport: inputs.responderAllowsTransport,
    initiatorAcceptsTunnelFallback: inputs.initiatorAcceptsTunnelFallback,
  });
  const idi = encodeIdBody(
    inputs.initiatorIdentity.type,
    inputs.initiatorIdentity.data,
  );
  const idr = encodeIdBody(
    inputs.responderIdentity.type,
    inputs.responderIdentity.data,
  );
  const initiatorSignedOctets = await buildSignedOctets({
    firstMessage: ikeSaInitRequest,
    peerNonce: inputs.nonceR,
    skP: keys.skPi,
    idPayloadBody: idi,
  });
  const responderSignedOctets = await buildSignedOctets({
    firstMessage: ikeSaInitResponse,
    peerNonce: inputs.nonceI,
    skP: keys.skPr,
    idPayloadBody: idr,
  });
  const initiatorAuth = await computePskAuth(inputs.psk, initiatorSignedOctets);
  const responderAuth = await computePskAuth(inputs.psk, responderSignedOctets);

  const requestPayloads: IkePayload[] = [
    payload(PayloadType.IDI, idi),
    payload(
      PayloadType.AUTH,
      encodeAuthBody(AUTH_METHOD_SHARED_KEY_MIC, initiatorAuth),
    ),
    payload(
      PayloadType.SA,
      encodeSaBody([childSaProposal(inputs.initiatorInboundChildSpi)]),
    ),
    payload(PayloadType.TSI, encodeTsBody(inputs.offeredSelector, "source")),
    payload(
      PayloadType.TSR,
      encodeTsBody(inputs.offeredSelector, "destination"),
    ),
  ];
  if (inputs.requestedMode === "transport") {
    requestPayloads.push(
      payload(
        PayloadType.NOTIFY,
        encodeNotifyBody({ messageType: USE_TRANSPORT_MODE }),
      ),
    );
  }
  const responsePayloads: IkePayload[] = [
    payload(PayloadType.IDR, idr),
    payload(
      PayloadType.AUTH,
      encodeAuthBody(AUTH_METHOD_SHARED_KEY_MIC, responderAuth),
    ),
    payload(
      PayloadType.SA,
      encodeSaBody([childSaProposal(inputs.responderInboundChildSpi)]),
    ),
    payload(PayloadType.TSI, encodeTsBody(narrowedSelector, "source")),
    payload(PayloadType.TSR, encodeTsBody(narrowedSelector, "destination")),
  ];
  if (mode.responderEchoedTransport) {
    responsePayloads.push(
      payload(
        PayloadType.NOTIFY,
        encodeNotifyBody({ messageType: USE_TRANSPORT_MODE }),
      ),
    );
  }

  const initiatorIkeSender = new IkeMessageSender({
    initiatorSpi: inputs.initiatorSpi,
    responderSpi: inputs.responderSpi,
    keyWithSalt: keys.skEi,
    originalSenderIsInitiator: true,
    initialCounter: counterBefore(
      inputs.initiatorIkeIv,
      "initiator IKE explicit IV",
    ),
  });
  const responderIkeSender = new IkeMessageSender({
    initiatorSpi: inputs.initiatorSpi,
    responderSpi: inputs.responderSpi,
    keyWithSalt: keys.skEr,
    originalSenderIsInitiator: false,
    initialCounter: counterBefore(
      inputs.responderIkeIv,
      "responder IKE explicit IV",
    ),
  });
  const ikeAuthRequest = await initiatorIkeSender.send({
    exchangeType: ExchangeType.IKE_AUTH,
    flags: IKE_FLAG_INITIATOR,
    messageId: 1,
    innerPayloads: requestPayloads,
  });
  const ikeAuthResponse = await responderIkeSender.send({
    exchangeType: ExchangeType.IKE_AUTH,
    flags: IKE_FLAG_RESPONSE,
    messageId: 1,
    innerPayloads: responsePayloads,
  });
  const openedRequest = await openIkeEncryptedMessage(
    ikeAuthRequest.message,
    keys.skEi,
  );
  const openedResponse = await openIkeEncryptedMessage(
    ikeAuthResponse.message,
    keys.skEr,
  );
  const initiatorAuthVerification = await verifyReceivedIkeAuth({
    opened: openedRequest,
    sender: "initiator",
    expectedIdentity: inputs.initiatorIdentity,
    expectedInitiatorSpi: inputs.initiatorSpi,
    expectedResponderSpi: inputs.responderSpi,
    firstMessage: ikeSaInitRequest,
    peerNonce: inputs.nonceR,
    skP: keys.skPi,
    psk: inputs.psk,
  });
  const responderAuthVerification = await verifyReceivedIkeAuth({
    opened: openedResponse,
    sender: "responder",
    expectedIdentity: inputs.responderIdentity,
    expectedInitiatorSpi: inputs.initiatorSpi,
    expectedResponderSpi: inputs.responderSpi,
    firstMessage: ikeSaInitResponse,
    peerNonce: inputs.nonceI,
    skP: keys.skPr,
    psk: inputs.psk,
  });
  if (
    !initiatorAuthVerification.accepted ||
    !responderAuthVerification.accepted
  ) {
    throw new Error(
      "Generated IKE_AUTH did not pass independent peer verification.",
    );
  }
  const childKeys = await deriveInitialChildKeys(
    keys.skD,
    inputs.nonceI,
    inputs.nonceR,
  );
  return {
    initiatorPublic,
    responderPublic,
    initiatorDh,
    responderDh,
    ikeSaInitRequest,
    ikeSaInitResponse,
    keys,
    initiatorSignedOctets,
    responderSignedOctets,
    initiatorAuth,
    responderAuth,
    initiatorAuthVerification,
    responderAuthVerification,
    ikeAuthRequest,
    ikeAuthResponse,
    openedRequest,
    openedResponse,
    childKeys,
    narrowedSelector,
    mode,
    initiatorIkeSender,
    responderIkeSender,
  };
}

export function freshHandshakeSecrets(): Pick<
  HandshakeInputs,
  | "initiatorPrivate"
  | "responderPrivate"
  | "nonceI"
  | "nonceR"
  | "initiatorSpi"
  | "responderSpi"
  | "initiatorInboundChildSpi"
  | "responderInboundChildSpi"
  | "initiatorIkeIv"
  | "responderIkeIv"
> {
  const initiatorSpi = randomNonzeroIkeSpi();
  let responderSpi: Uint8Array;
  do {
    responderSpi = randomNonzeroIkeSpi();
  } while (bytesEqual(initiatorSpi, responderSpi));
  const initiatorInboundChildSpi = randomAllocatedChildSpi();
  let responderInboundChildSpi: Uint8Array;
  do {
    responderInboundChildSpi = randomAllocatedChildSpi();
  } while (bytesEqual(initiatorInboundChildSpi, responderInboundChildSpi));
  return {
    initiatorPrivate: randomBytes(32),
    responderPrivate: randomBytes(32),
    nonceI: randomBytes(32),
    nonceR: randomBytes(32),
    initiatorSpi,
    responderSpi,
    initiatorInboundChildSpi,
    responderInboundChildSpi,
    initiatorIkeIv: u64be(1n),
    responderIkeIv: u64be(1n),
  };
}

function buildIkeSaInit(options: {
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
  flags: number;
  publicKey: Uint8Array;
  nonce: Uint8Array;
}): Uint8Array {
  return encodeIkeMessage({
    initiatorSpi: options.initiatorSpi,
    responderSpi: options.responderSpi,
    exchangeType: ExchangeType.IKE_SA_INIT,
    flags: options.flags,
    messageId: 0,
    payloads: [
      payload(PayloadType.SA, encodeSaBody([ikeSaProposal()])),
      payload(PayloadType.KE, encodeKeBody(31, options.publicKey)),
      payload(PayloadType.NONCE, options.nonce),
    ],
  });
}

function validateNonce(nonce: Uint8Array, label: string): void {
  if (nonce.length < 16 || nonce.length > 256) {
    throw new RangeError(`${label} must contain between 16 and 256 octets.`);
  }
}

function validateHandshakeInputs(inputs: HandshakeInputs): void {
  requireLength(inputs.initiatorPrivate, 32, "initiator X25519 private scalar");
  requireLength(inputs.responderPrivate, 32, "responder X25519 private scalar");
  validateNonce(inputs.nonceI, "initiator nonce");
  validateNonce(inputs.nonceR, "responder nonce");
  requireLength(inputs.initiatorSpi, 8, "IKE initiator SPI");
  requireLength(inputs.responderSpi, 8, "IKE responder SPI");
  requireLength(
    inputs.initiatorInboundChildSpi,
    4,
    "initiator inbound Child-SA SPI",
  );
  requireLength(
    inputs.responderInboundChildSpi,
    4,
    "responder inbound Child-SA SPI",
  );
  if (
    readU64be(inputs.initiatorSpi) === 0n ||
    readU64be(inputs.responderSpi) === 0n
  ) {
    throw new RangeError("Established IKE SPIs must be nonzero.");
  }
  if (
    readU32be(inputs.initiatorInboundChildSpi) < 256 ||
    readU32be(inputs.responderInboundChildSpi) < 256
  ) {
    throw new RangeError(
      "Child-SA SPIs must be allocated values greater than 255.",
    );
  }
  requireLength(inputs.initiatorIkeIv, 8, "initiator IKE explicit IV");
  requireLength(inputs.responderIkeIv, 8, "responder IKE explicit IV");
  if (
    !inputs.initiatorIdentity.label ||
    inputs.initiatorIdentity.data.length === 0 ||
    !inputs.responderIdentity.label ||
    inputs.responderIdentity.data.length === 0
  ) {
    throw new Error("Both IKE identities are required.");
  }
}

function randomNonzeroIkeSpi(): Uint8Array {
  let spi: Uint8Array;
  do {
    spi = randomBytes(8);
  } while (readU64be(spi) === 0n);
  return spi;
}

function randomAllocatedChildSpi(): Uint8Array {
  let spi: Uint8Array;
  do {
    spi = randomBytes(4);
  } while (readU32be(spi) < 256);
  return spi;
}

const MAX_IKE_IV = 0xffffffffffffffffn;

export interface ProtectedIkeSend {
  exchangeType: number;
  flags: number;
  messageId: number;
  innerPayloads: readonly IkePayload[];
  paddingLength?: number;
}

type IkeSealer = typeof sealIkeEncryptedMessage;

interface CachedIkeSend {
  fingerprint: string;
  result: SealedIkeMessage;
}

interface PendingIkeSend {
  fingerprint: string;
  promise: Promise<SealedIkeMessage>;
}

/**
 * Owns one IKE traffic direction's explicit-IV space. Allocation is independent
 * of Message ID, burns before AEAD, and caches exact successful retransmissions.
 */
export class IkeMessageSender {
  readonly #initiatorSpi: Uint8Array;
  readonly #responderSpi: Uint8Array;
  readonly #keyWithSalt: Uint8Array;
  readonly #sealer: IkeSealer;
  readonly #cache = new Map<string, CachedIkeSend>();
  readonly #pending = new Map<string, PendingIkeSend>();
  readonly #knownFingerprints = new Map<string, string>();
  readonly #originalSenderIsInitiator: boolean;
  #lastRequestMessageId: number | undefined;
  #counter: bigint;

  constructor(options: {
    initiatorSpi: Uint8Array;
    responderSpi: Uint8Array;
    keyWithSalt: Uint8Array;
    originalSenderIsInitiator: boolean;
    initialCounter?: bigint;
    /** Dependency seam used only to prove allocation survives an AEAD failure. */
    sealer?: IkeSealer;
  }) {
    this.#initiatorSpi = requireLength(
      options.initiatorSpi,
      8,
      "IKE initiator SPI",
    ).slice();
    this.#responderSpi = requireLength(
      options.responderSpi,
      8,
      "IKE responder SPI",
    ).slice();
    this.#keyWithSalt = requireLength(
      options.keyWithSalt,
      20,
      "IKE encryption key material",
    ).slice();
    this.#originalSenderIsInitiator = options.originalSenderIsInitiator;
    this.#counter = options.initialCounter ?? 0n;
    if (this.#counter < 0n || this.#counter > MAX_IKE_IV) {
      throw new RangeError(
        "IKE explicit-IV counter must be an unsigned 64-bit value.",
      );
    }
    this.#sealer = options.sealer ?? sealIkeEncryptedMessage;
  }

  get currentIvCounter(): bigint {
    return this.#counter;
  }

  matchesContext(options: {
    initiatorSpi: Uint8Array;
    responderSpi: Uint8Array;
    keyWithSalt: Uint8Array;
    originalSenderIsInitiator: boolean;
  }): boolean {
    requireLength(options.initiatorSpi, 8, "IKE initiator SPI");
    requireLength(options.responderSpi, 8, "IKE responder SPI");
    requireLength(options.keyWithSalt, 20, "IKE encryption key material");
    return (
      bytesEqual(this.#initiatorSpi, options.initiatorSpi) &&
      bytesEqual(this.#responderSpi, options.responderSpi) &&
      bytesEqual(this.#keyWithSalt, options.keyWithSalt) &&
      this.#originalSenderIsInitiator === options.originalSenderIsInitiator
    );
  }

  async send(options: ProtectedIkeSend): Promise<SealedIkeMessage> {
    const { identity, fingerprint, isResponse } = validateAndIdentifyIkeSend(
      options,
      this.#initiatorSpi,
      this.#responderSpi,
      this.#originalSenderIsInitiator,
    );
    const known = this.#knownFingerprints.get(identity);
    if (known) requireSameIkeFingerprint(known, fingerprint);
    const cached = this.#cache.get(identity);
    if (cached) {
      requireSameIkeFingerprint(cached.fingerprint, fingerprint);
      return cloneSealedIke(cached.result);
    }
    const pending = this.#pending.get(identity);
    if (pending) {
      requireSameIkeFingerprint(pending.fingerprint, fingerprint);
      return cloneSealedIke(await pending.promise);
    }
    if (!known) {
      if (
        !isResponse &&
        this.#lastRequestMessageId !== undefined &&
        options.messageId !== this.#lastRequestMessageId + 1
      ) {
        throw new Error(
          `New IKE requests must advance this endpoint's Message ID from ${this.#lastRequestMessageId} to ${this.#lastRequestMessageId + 1}.`,
        );
      }
      this.#knownFingerprints.set(identity, fingerprint);
      if (!isResponse) this.#lastRequestMessageId = options.messageId;
    }
    if (this.#counter === MAX_IKE_IV) {
      throw new Error(
        "IKE explicit-IV space is exhausted; replace the IKE SA before reuse.",
      );
    }

    // Reserve first. A Web Crypto failure intentionally cannot roll this back.
    this.#counter += 1n;
    const explicitIv = u64be(this.#counter);
    const promise = this.#sealer({
      initiatorSpi: this.#initiatorSpi,
      responderSpi: this.#responderSpi,
      exchangeType: options.exchangeType,
      flags: options.flags,
      messageId: options.messageId,
      keyWithSalt: this.#keyWithSalt,
      explicitIv,
      innerPayloads: options.innerPayloads,
      paddingLength: options.paddingLength,
    });
    this.#pending.set(identity, { fingerprint, promise });
    try {
      const result = await promise;
      this.#cache.set(identity, {
        fingerprint,
        result: cloneSealedIke(result),
      });
      return cloneSealedIke(result);
    } finally {
      this.#pending.delete(identity);
    }
  }
}

function validateAndIdentifyIkeSend(
  options: ProtectedIkeSend,
  initiatorSpi: Uint8Array,
  responderSpi: Uint8Array,
  originalSenderIsInitiator: boolean,
): { identity: string; fingerprint: string; isResponse: boolean } {
  if (options.innerPayloads.length === 0) {
    throw new Error("IKE encrypted payload cannot be empty.");
  }
  const encoded = encodePayloadChain(options.innerPayloads);
  const paddingLength = options.paddingLength ?? 0;
  if (
    !Number.isInteger(paddingLength) ||
    paddingLength < 0 ||
    paddingLength > 255
  ) {
    throw new RangeError("IKE padding length must be an octet.");
  }
  encodeIkeHeader({
    initiatorSpi,
    responderSpi,
    nextPayload: PayloadType.SK,
    exchangeType: options.exchangeType,
    flags: options.flags,
    messageId: options.messageId,
    length: IKE_HEADER_BYTES,
  });
  const hasInitiatorFlag = (options.flags & IKE_FLAG_INITIATOR) !== 0;
  if (hasInitiatorFlag !== originalSenderIsInitiator) {
    throw new Error(
      "The IKE Initiator flag must identify the original IKE initiator.",
    );
  }
  const isResponse = (options.flags & IKE_FLAG_RESPONSE) !== 0;
  return {
    identity: `${isResponse ? "response" : "request"}:${options.messageId}`,
    fingerprint: `${options.exchangeType}:${options.flags}:${encoded.firstPayload}:${bytesToHex(encoded.bytes)}:${paddingLength}`,
    isResponse,
  };
}

function requireSameIkeFingerprint(expected: string, actual: string): void {
  if (expected !== actual) {
    throw new Error(
      "A retransmission identity was reused with different protected content; refusing stale-byte substitution.",
    );
  }
}

function cloneSealedIke(result: SealedIkeMessage): SealedIkeMessage {
  return {
    ...result,
    message: result.message.slice(),
    aad: result.aad.slice(),
    nonce: result.nonce.slice(),
    explicitIv: result.explicitIv.slice(),
    plaintext: result.plaintext.slice(),
    padding: result.padding.slice(),
    ciphertext: result.ciphertext.slice(),
    tag: result.tag.slice(),
  };
}

function counterBefore(explicitIv: Uint8Array, label: string): bigint {
  requireLength(explicitIv, 8, label);
  const value = readU64be(explicitIv);
  if (value === 0n)
    throw new RangeError(`${label} cannot be zero in this monotonic profile.`);
  return value - 1n;
}
