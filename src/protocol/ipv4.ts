import {
  bytesEqual,
  bytesToIpv4,
  concatBytes,
  ipv4ToBytes,
  readU16be,
  requireLength,
  u16be,
} from "./bytes";
import type { EspAccepted, EspSender, SealedEspPacket } from "./esp";

export const IP_PROTOCOL_ESP = 50;
export const IP_PROTOCOL_IPV4 = 4;

export interface Ipv4Packet {
  bytes: Uint8Array;
  header: Uint8Array;
  payload: Uint8Array;
  source: string;
  destination: string;
  protocol: number;
  identification: number;
}

export interface ProtectedIpPacket {
  mode: "transport" | "tunnel";
  original: Ipv4Packet;
  outer: Ipv4Packet;
  esp: SealedEspPacket;
  protectedBytes: Uint8Array;
  protectedMeaning: string;
  clearMeaning: string;
}

export interface ReconstructedIpPacket {
  mode: "transport" | "tunnel";
  packet: Ipv4Packet;
  checksumVerified: true;
}

export function buildIpv4Packet(options: {
  source: string;
  destination: string;
  protocol: number;
  payload: Uint8Array;
  identification?: number;
  ttl?: number;
}): Ipv4Packet {
  validateOctet(options.protocol, "IPv4 protocol");
  const identification = options.identification ?? 0x4242;
  if (
    !Number.isInteger(identification) ||
    identification < 0 ||
    identification > 0xffff
  ) {
    throw new RangeError("IPv4 identification must be a 16-bit value.");
  }
  const ttl = options.ttl ?? 64;
  validateOctet(ttl, "IPv4 TTL");
  const totalLength = 20 + options.payload.length;
  if (totalLength > 0xffff)
    throw new RangeError("IPv4 packet exceeds the 16-bit total length.");
  const headerWithoutChecksum = concatBytes(
    Uint8Array.of(0x45, 0),
    u16be(totalLength),
    u16be(identification),
    u16be(0x4000),
    Uint8Array.of(ttl, options.protocol),
    Uint8Array.of(0, 0),
    ipv4ToBytes(options.source),
    ipv4ToBytes(options.destination),
  );
  const header = headerWithoutChecksum.slice();
  header.set(u16be(internetChecksum(headerWithoutChecksum)), 10);
  return {
    bytes: concatBytes(header, options.payload),
    header,
    payload: options.payload.slice(),
    source: options.source,
    destination: options.destination,
    protocol: options.protocol,
    identification,
  };
}

export function parseIpv4Packet(bytes: Uint8Array): Ipv4Packet {
  if (bytes.length < 20 || bytes[0] !== 0x45) {
    throw new Error(
      "This bounded profile accepts only 20-octet IPv4 headers without options.",
    );
  }
  const totalLength = readU16be(bytes, 2);
  if (totalLength !== bytes.length)
    throw new Error("IPv4 total length does not match the packet.");
  const header = bytes.slice(0, 20);
  if (internetChecksum(header) !== 0)
    throw new Error("IPv4 header checksum is invalid.");
  return {
    bytes: bytes.slice(),
    header,
    payload: bytes.slice(20),
    source: bytesToIpv4(bytes.slice(12, 16)),
    destination: bytesToIpv4(bytes.slice(16, 20)),
    protocol: bytes[9]!,
    identification: readU16be(bytes, 4),
  };
}

export async function protectIpv4Packet(options: {
  mode: "transport" | "tunnel";
  original: Ipv4Packet;
  sender: EspSender;
  tunnelSource?: string;
  tunnelDestination?: string;
}): Promise<ProtectedIpPacket> {
  const original = parseIpv4Packet(options.original.bytes);
  const protectedBytes =
    options.mode === "tunnel" ? original.bytes : original.payload;
  const nextHeader =
    options.mode === "tunnel" ? IP_PROTOCOL_IPV4 : original.protocol;
  const esp = await options.sender.send(protectedBytes, nextHeader);
  const outer =
    options.mode === "tunnel"
      ? buildIpv4Packet({
          source: requireText(options.tunnelSource, "tunnel source"),
          destination: requireText(
            options.tunnelDestination,
            "tunnel destination",
          ),
          protocol: IP_PROTOCOL_ESP,
          payload: esp.packet,
          identification: original.identification,
        })
      : parseIpv4Packet(
          rewriteIpv4Payload(original.header, IP_PROTOCOL_ESP, esp.packet),
        );
  return {
    mode: options.mode,
    original,
    outer,
    esp,
    protectedBytes,
    protectedMeaning:
      options.mode === "tunnel"
        ? "The complete inner IPv4 packet is encrypted as ESP payload."
        : "Only the original transport segment is encrypted as ESP payload.",
    clearMeaning:
      options.mode === "tunnel"
        ? "Only the new gateway-to-gateway outer IPv4 header remains clear."
        : "The original endpoint addresses remain in the clear outer IPv4 header.",
  };
}

/** Rebuilds and parses the original packet before the UI may call decryption successful. */
export function reconstructIpv4AfterEsp(options: {
  mode: "transport" | "tunnel";
  outer: Ipv4Packet;
  accepted: EspAccepted;
}): ReconstructedIpPacket {
  const outer = parseIpv4Packet(options.outer.bytes);
  if (outer.protocol !== IP_PROTOCOL_ESP) {
    throw new Error("The outer IPv4 packet does not identify ESP.");
  }
  if (options.mode === "tunnel") {
    if (options.accepted.nextHeader !== IP_PROTOCOL_IPV4) {
      throw new Error("Tunnel-mode ESP must identify an inner IPv4 packet.");
    }
    return {
      mode: "tunnel",
      packet: parseIpv4Packet(options.accepted.payload),
      checksumVerified: true,
    };
  }
  if (
    options.accepted.nextHeader === IP_PROTOCOL_IPV4 ||
    options.accepted.nextHeader === IP_PROTOCOL_ESP
  ) {
    throw new Error("Transport-mode ESP must restore an upper-layer protocol.");
  }
  return {
    mode: "transport",
    packet: parseIpv4Packet(
      rewriteIpv4Payload(
        outer.header,
        options.accepted.nextHeader,
        options.accepted.payload,
      ),
    ),
    checksumVerified: true,
  };
}

export function internetChecksum(bytes: Uint8Array): number {
  if (bytes.length % 2 !== 0)
    throw new RangeError("Internet checksum input must be even-length.");
  let sum = 0;
  for (let offset = 0; offset < bytes.length; offset += 2) {
    sum += (bytes[offset]! << 8) | bytes[offset + 1]!;
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

export function sameIpv4Packet(left: Ipv4Packet, right: Ipv4Packet): boolean {
  requireLength(left.header, 20, "left IPv4 header");
  requireLength(right.header, 20, "right IPv4 header");
  return bytesEqual(left.bytes, right.bytes);
}

function rewriteIpv4Payload(
  originalHeader: Uint8Array,
  protocol: number,
  payload: Uint8Array,
): Uint8Array {
  requireLength(originalHeader, 20, "IPv4 header");
  validateOctet(protocol, "IPv4 protocol");
  const totalLength = 20 + payload.length;
  if (totalLength > 0xffff)
    throw new RangeError("IPv4 packet exceeds the 16-bit total length.");
  const header = originalHeader.slice();
  header.set(u16be(totalLength), 2);
  header[9] = protocol;
  header[10] = 0;
  header[11] = 0;
  header.set(u16be(internetChecksum(header)), 10);
  return concatBytes(header, payload);
}

function requireText(value: string | undefined, label: string): string {
  if (!value) throw new Error(`${label} is required in tunnel mode.`);
  return value;
}

function validateOctet(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new RangeError(`${label} must be an octet.`);
  }
}
