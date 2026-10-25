import {
  concatBytes,
  ipv4ToBytes,
  readU16be,
  readU32be,
  requireLength,
  u16be,
  u32be,
} from "./bytes";
import {
  validateTrafficSelector,
  type NumericRange,
  type TrafficSelector,
} from "./spd";

export const IKE_HEADER_BYTES = 28;
export const IKE_VERSION_2_0 = 0x20;
export const IKE_FLAG_INITIATOR = 0x08;
export const IKE_FLAG_RESPONSE = 0x20;
export const USE_TRANSPORT_MODE = 16_391;

export const PayloadType = {
  NONE: 0,
  SA: 33,
  KE: 34,
  IDI: 35,
  IDR: 36,
  AUTH: 39,
  NONCE: 40,
  NOTIFY: 41,
  DELETE: 42,
  TSI: 44,
  TSR: 45,
  SK: 46,
} as const;

export const ExchangeType = {
  IKE_SA_INIT: 34,
  IKE_AUTH: 35,
  CREATE_CHILD_SA: 36,
  INFORMATIONAL: 37,
} as const;

export interface IkePayload {
  type: number;
  body: Uint8Array;
  critical?: boolean;
}

export interface IkeMessageOptions {
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
  exchangeType: number;
  flags: number;
  messageId: number;
  payloads: readonly IkePayload[];
}

export interface ParsedIkeHeader {
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
  nextPayload: number;
  version: number;
  exchangeType: number;
  flags: number;
  messageId: number;
  length: number;
}

export interface ParsedPayload {
  type: number;
  nextPayload: number;
  critical: boolean;
  body: Uint8Array;
  encoded: Uint8Array;
}

export interface Transform {
  type: number;
  id: number;
  keyLengthBits?: number;
}

export interface Proposal {
  number: number;
  protocolId: number;
  spi?: Uint8Array;
  transforms: readonly Transform[];
}

export function encodeIkeMessage(options: IkeMessageOptions): Uint8Array {
  requireLength(options.initiatorSpi, 8, "IKE initiator SPI");
  requireLength(options.responderSpi, 8, "IKE responder SPI");
  validateOctet(options.exchangeType, "IKE exchange type");
  validateOctet(options.flags, "IKE flags");
  const chain = encodePayloadChain(options.payloads);
  const length = IKE_HEADER_BYTES + chain.bytes.length;
  return concatBytes(
    encodeIkeHeader({
      ...options,
      nextPayload: chain.firstPayload,
      length,
    }),
    chain.bytes,
  );
}

export function encodeIkeHeader(options: {
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
  nextPayload: number;
  exchangeType: number;
  flags: number;
  messageId: number;
  length: number;
}): Uint8Array {
  requireLength(options.initiatorSpi, 8, "IKE initiator SPI");
  requireLength(options.responderSpi, 8, "IKE responder SPI");
  validateOctet(options.nextPayload, "IKE next payload");
  validateOctet(options.exchangeType, "IKE exchange type");
  validateOctet(options.flags, "IKE flags");
  if (options.length < IKE_HEADER_BYTES)
    throw new RangeError("IKE length is too short.");
  return concatBytes(
    options.initiatorSpi,
    options.responderSpi,
    Uint8Array.of(
      options.nextPayload,
      IKE_VERSION_2_0,
      options.exchangeType,
      options.flags,
    ),
    u32be(options.messageId),
    u32be(options.length),
  );
}

export function parseIkeHeader(message: Uint8Array): ParsedIkeHeader {
  if (message.length < IKE_HEADER_BYTES)
    throw new Error("IKE message is shorter than its header.");
  const header: ParsedIkeHeader = {
    initiatorSpi: message.slice(0, 8),
    responderSpi: message.slice(8, 16),
    nextPayload: message[16]!,
    version: message[17]!,
    exchangeType: message[18]!,
    flags: message[19]!,
    messageId: readU32be(message, 20),
    length: readU32be(message, 24),
  };
  if (header.version !== IKE_VERSION_2_0)
    throw new Error("Only IKEv2 version 2.0 is accepted.");
  if (header.length !== message.length) {
    throw new Error(
      `IKE header length ${header.length} does not match ${message.length} octets.`,
    );
  }
  return header;
}

export function encodePayloadChain(payloads: readonly IkePayload[]): {
  firstPayload: number;
  bytes: Uint8Array;
} {
  if (payloads.length === 0)
    return { firstPayload: PayloadType.NONE, bytes: new Uint8Array() };
  for (const payload of payloads) validateOctet(payload.type, "payload type");
  const encoded = payloads.map((payload, index) => {
    const nextPayload = payloads[index + 1]?.type ?? PayloadType.NONE;
    const length = 4 + payload.body.length;
    return concatBytes(
      Uint8Array.of(nextPayload, payload.critical ? 0x80 : 0),
      u16be(length),
      payload.body,
    );
  });
  return { firstPayload: payloads[0]!.type, bytes: concatBytes(...encoded) };
}

export function decodePayloadChain(
  bytes: Uint8Array,
  firstPayload: number,
): ParsedPayload[] {
  const payloads: ParsedPayload[] = [];
  let type = firstPayload;
  let offset = 0;
  while (type !== PayloadType.NONE) {
    if (offset + 4 > bytes.length)
      throw new Error("Truncated IKE payload header.");
    const nextPayload = bytes[offset]!;
    const flags = bytes[offset + 1]!;
    const length = readU16be(bytes, offset + 2);
    if (length < 4 || offset + length > bytes.length) {
      throw new Error("Invalid or truncated IKE payload length.");
    }
    const encoded = bytes.slice(offset, offset + length);
    payloads.push({
      type,
      nextPayload,
      critical: (flags & 0x80) !== 0,
      body: encoded.slice(4),
      encoded,
    });
    offset += length;
    if (type === PayloadType.SK) {
      type = PayloadType.NONE;
    } else {
      type = nextPayload;
    }
  }
  if (offset !== bytes.length)
    throw new Error("Trailing octets follow the IKE payload chain.");
  return payloads;
}

export function encodeSaBody(proposals: readonly Proposal[]): Uint8Array {
  if (proposals.length === 0)
    throw new Error("An SA payload requires at least one proposal.");
  return concatBytes(
    ...proposals.map((proposal, proposalIndex) => {
      if (proposal.transforms.length === 0) {
        throw new Error("An SA proposal requires at least one transform.");
      }
      const spi = proposal.spi ?? new Uint8Array();
      if (spi.length > 0xff || proposal.transforms.length > 0xff) {
        throw new RangeError("Proposal SPI or transform count is too large.");
      }
      const transforms = concatBytes(
        ...proposal.transforms.map((transform, transformIndex) =>
          encodeTransform(
            transform,
            transformIndex < proposal.transforms.length - 1,
          ),
        ),
      );
      const length = 8 + spi.length + transforms.length;
      return concatBytes(
        Uint8Array.of(proposalIndex < proposals.length - 1 ? 2 : 0, 0),
        u16be(length),
        Uint8Array.of(
          proposal.number,
          proposal.protocolId,
          spi.length,
          proposal.transforms.length,
        ),
        spi,
        transforms,
      );
    }),
  );
}

export function ikeSaProposal(): Proposal {
  return {
    number: 1,
    protocolId: 1,
    transforms: [
      { type: 1, id: 20, keyLengthBits: 128 },
      { type: 2, id: 5 },
      { type: 4, id: 31 },
    ],
  };
}

export function childSaProposal(inboundSpi: Uint8Array): Proposal {
  requireLength(inboundSpi, 4, "Child-SA inbound SPI");
  return {
    number: 1,
    protocolId: 3,
    spi: inboundSpi,
    transforms: [
      { type: 1, id: 20, keyLengthBits: 128 },
      { type: 5, id: 0 },
    ],
  };
}

export function encodeKeBody(group: number, publicKey: Uint8Array): Uint8Array {
  if (publicKey.length === 0)
    throw new Error("KE public value must not be empty.");
  return concatBytes(u16be(group), Uint8Array.of(0, 0), publicKey);
}

export function encodeIdBody(
  idType: number,
  identificationData: Uint8Array,
): Uint8Array {
  validateOctet(idType, "ID type");
  if (identificationData.length === 0)
    throw new Error("Identification data must not be empty.");
  return concatBytes(Uint8Array.of(idType, 0, 0, 0), identificationData);
}

export function encodeAuthBody(
  method: number,
  authenticationData: Uint8Array,
): Uint8Array {
  validateOctet(method, "AUTH method");
  if (authenticationData.length === 0)
    throw new Error("AUTH data must not be empty.");
  return concatBytes(Uint8Array.of(method, 0, 0, 0), authenticationData);
}

export function encodeNotifyBody(options: {
  protocolId?: number;
  spi?: Uint8Array;
  messageType: number;
  data?: Uint8Array;
}): Uint8Array {
  const protocolId = options.protocolId ?? 0;
  const spi = options.spi ?? new Uint8Array();
  const data = options.data ?? new Uint8Array();
  validateOctet(protocolId, "Notify protocol id");
  if (spi.length > 0xff) throw new RangeError("Notify SPI is too long.");
  return concatBytes(
    Uint8Array.of(protocolId, spi.length),
    u16be(options.messageType),
    spi,
    data,
  );
}

export function encodeDeleteBody(
  protocolId: number,
  spis: readonly Uint8Array[],
): Uint8Array {
  validateOctet(protocolId, "Delete protocol id");
  if (spis.length === 0 || spis.length > 0xffff) {
    throw new RangeError(
      "Delete payload must name between one and 65,535 SPIs.",
    );
  }
  const spiSize = spis[0]!.length;
  if (
    spiSize === 0 ||
    spiSize > 0xff ||
    spis.some((spi) => spi.length !== spiSize)
  ) {
    throw new RangeError(
      "Delete payload SPIs must have one common nonzero size.",
    );
  }
  return concatBytes(
    Uint8Array.of(protocolId, spiSize),
    u16be(spis.length),
    ...spis,
  );
}

export function encodeTsBody(
  selector: TrafficSelector,
  side: "source" | "destination",
): Uint8Array {
  validateTrafficSelector(selector);
  if (side !== "source" && side !== "destination") {
    throw new TypeError("Traffic-selector side must be source or destination.");
  }
  const address =
    side === "source" ? selector.sourceAddress : selector.destinationAddress;
  const port =
    side === "source" ? selector.sourcePort : selector.destinationPort;
  return concatBytes(
    Uint8Array.of(1, 0, 0, 0),
    Uint8Array.of(7, selector.protocol),
    u16be(16),
    u16be(port.start),
    u16be(port.end),
    ipv4NumberBytes(address.start),
    ipv4NumberBytes(address.end),
  );
}

export function payload(
  type: number,
  body: Uint8Array,
  critical = false,
): IkePayload {
  return { type, body, critical };
}

function encodeTransform(transform: Transform, more: boolean): Uint8Array {
  validateOctet(transform.type, "transform type");
  const attributes =
    transform.keyLengthBits === undefined
      ? new Uint8Array()
      : concatBytes(u16be(0x800e), u16be(transform.keyLengthBits));
  const length = 8 + attributes.length;
  return concatBytes(
    Uint8Array.of(more ? 3 : 0, 0),
    u16be(length),
    Uint8Array.of(transform.type, 0),
    u16be(transform.id),
    attributes,
  );
}

function ipv4NumberBytes(value: number): Uint8Array {
  return ipv4ToBytes(
    [
      value >>> 24,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ].join("."),
  );
}

function validateOctet(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new RangeError(`${label} must be an octet.`);
  }
}

export function decodeSingleTsBody(body: Uint8Array): {
  protocol: number;
  ports: NumericRange;
  addresses: NumericRange;
} {
  if (
    body.length !== 20 ||
    body[0] !== 1 ||
    body[4] !== 7 ||
    readU16be(body, 6) !== 16
  ) {
    throw new Error(
      "Expected exactly one IPv4 address-range traffic selector.",
    );
  }
  return {
    protocol: body[5]!,
    ports: { start: readU16be(body, 8), end: readU16be(body, 10) },
    addresses: { start: readU32be(body, 12), end: readU32be(body, 16) },
  };
}
