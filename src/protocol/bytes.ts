const HEX_RE = /^[0-9a-f]*$/i;

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function hexToBytes(hex: string): Uint8Array {
  const compact = hex.replaceAll(/\s+/g, "");
  if (compact.length % 2 !== 0 || !HEX_RE.test(compact)) {
    throw new TypeError(
      "Hex input must contain an even number of hexadecimal digits.",
    );
  }
  const output = new Uint8Array(compact.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(
      compact.slice(index * 2, index * 2 + 2),
      16,
    );
  }
  return output;
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function readUtf8(value: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(value);
}

export function u16be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError("A 16-bit unsigned integer is required.");
  }
  return Uint8Array.of(value >>> 8, value & 0xff);
}

export function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError("A 32-bit unsigned integer is required.");
  }
  return Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
}

export function u64be(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new RangeError("A 64-bit unsigned integer is required.");
  }
  const output = new Uint8Array(8);
  let remaining = value;
  for (let index = output.length - 1; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

export function readU16be(bytes: Uint8Array, offset = 0): number {
  requireAvailable(bytes, offset, 2);
  return bytes[offset]! * 0x100 + bytes[offset + 1]!;
}

export function readU32be(bytes: Uint8Array, offset = 0): number {
  requireAvailable(bytes, offset, 4);
  return (
    bytes[offset]! * 0x1000000 +
    bytes[offset + 1]! * 0x10000 +
    bytes[offset + 2]! * 0x100 +
    bytes[offset + 3]!
  );
}

export function readU64be(bytes: Uint8Array, offset = 0): bigint {
  requireAvailable(bytes, offset, 8);
  let value = 0n;
  for (let index = offset; index < offset + 8; index += 1) {
    value = (value << 8n) | BigInt(bytes[index]!);
  }
  return value;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function requireLength(
  value: Uint8Array,
  expected: number,
  label: string,
): Uint8Array {
  if (value.length !== expected) {
    throw new RangeError(`${label} must be exactly ${expected} octets.`);
  }
  return value;
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) {
    throw new RangeError("Random byte length must be between 1 and 65,536.");
  }
  return crypto.getRandomValues(new Uint8Array(length));
}

export function ipv4ToBytes(address: string): Uint8Array {
  const parts = address.split(".");
  if (parts.length !== 4)
    throw new TypeError(`Invalid IPv4 address: ${address}`);
  const octets = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part))
      throw new TypeError(`Invalid IPv4 address: ${address}`);
    const value = Number(part);
    if (value > 255 || String(value) !== part) {
      throw new TypeError(`Invalid IPv4 address: ${address}`);
    }
    return value;
  });
  return Uint8Array.from(octets);
}

export function bytesToIpv4(bytes: Uint8Array): string {
  requireLength(bytes, 4, "IPv4 address");
  return Array.from(bytes).join(".");
}

export function ipv4ToNumber(address: string): number {
  return readU32be(ipv4ToBytes(address));
}

function requireAvailable(
  bytes: Uint8Array,
  offset: number,
  length: number,
): void {
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset + length > bytes.length
  ) {
    throw new RangeError("Byte range is outside the input.");
  }
}
