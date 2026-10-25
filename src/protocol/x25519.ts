import { bytesEqual, requireLength } from "./bytes";

const FIELD_PRIME = (1n << 255n) - 19n;
const A24 = 121665n;

export interface X25519Result {
  sharedSecret: Uint8Array;
  maskedTopBit: boolean;
  nonCanonicalInput: boolean;
  allZero: boolean;
}

export interface X25519Policy {
  rejectAllZero?: boolean;
}

export function x25519(
  scalarBytes: Uint8Array,
  uCoordinateBytes: Uint8Array,
): Uint8Array {
  const scalar = decodeScalar25519(scalarBytes);
  const u = decodeUCoordinate(uCoordinateBytes).value;

  let x2 = 1n;
  let z2 = 0n;
  let x3 = u;
  let z3 = 1n;
  let swap = 0n;

  for (let bit = 254; bit >= 0; bit -= 1) {
    const scalarBit = (scalar >> BigInt(bit)) & 1n;
    swap ^= scalarBit;
    [x2, x3] = conditionalSwap(swap, x2, x3);
    [z2, z3] = conditionalSwap(swap, z2, z3);
    swap = scalarBit;

    const a = mod(x2 + z2);
    const aa = mod(a * a);
    const b = mod(x2 - z2);
    const bb = mod(b * b);
    const e = mod(aa - bb);
    const c = mod(x3 + z3);
    const d = mod(x3 - z3);
    const da = mod(d * a);
    const cb = mod(c * b);
    x3 = mod((da + cb) * (da + cb));
    z3 = mod(u * mod((da - cb) * (da - cb)));
    x2 = mod(aa * bb);
    z2 = mod(e * mod(aa + A24 * e));
  }

  [x2] = conditionalSwap(swap, x2, x3);
  [z2] = conditionalSwap(swap, z2, z3);
  return encodeLittleEndian(mod(x2 * modPow(z2, FIELD_PRIME - 2n)), 32);
}

export function x25519WithPolicy(
  scalar: Uint8Array,
  peerPublic: Uint8Array,
  policy: X25519Policy = {},
): X25519Result {
  const decoded = decodeUCoordinate(peerPublic);
  const sharedSecret = x25519(scalar, peerPublic);
  const allZero = bytesEqual(sharedSecret, new Uint8Array(32));
  if (allZero && policy.rejectAllZero) {
    throw new Error("Local policy refused an all-zero X25519 shared secret.");
  }
  return {
    sharedSecret,
    maskedTopBit: decoded.maskedTopBit,
    nonCanonicalInput: decoded.nonCanonical,
    allZero,
  };
}

export function x25519PublicKey(privateScalar: Uint8Array): Uint8Array {
  const basePoint = new Uint8Array(32);
  basePoint[0] = 9;
  return x25519(privateScalar, basePoint);
}

export function decodeUCoordinate(bytes: Uint8Array): {
  value: bigint;
  maskedTopBit: boolean;
  nonCanonical: boolean;
} {
  requireLength(bytes, 32, "X25519 u-coordinate");
  const copy = bytes.slice();
  const maskedTopBit = (copy[31]! & 0x80) !== 0;
  copy[31] = copy[31]! & 0x7f;
  const encodedValue = decodeLittleEndian(copy);
  return {
    value: mod(encodedValue),
    maskedTopBit,
    nonCanonical: encodedValue >= FIELD_PRIME,
  };
}

function decodeScalar25519(bytes: Uint8Array): bigint {
  requireLength(bytes, 32, "X25519 scalar");
  const copy = bytes.slice();
  copy[0] = copy[0]! & 248;
  copy[31] = (copy[31]! & 127) | 64;
  return decodeLittleEndian(copy);
}

function decodeLittleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]!);
  }
  return value;
}

function encodeLittleEndian(value: bigint, length: number): Uint8Array {
  const output = new Uint8Array(length);
  let remaining = value;
  for (let index = 0; index < length; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function mod(value: bigint): bigint {
  const reduced = value % FIELD_PRIME;
  return reduced < 0n ? reduced + FIELD_PRIME : reduced;
}

function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let factor = mod(base);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    remaining >>= 1n;
  }
  return result;
}

function conditionalSwap(
  swap: bigint,
  left: bigint,
  right: bigint,
): [bigint, bigint] {
  const mask = -swap;
  const difference = mask & (left ^ right);
  return [left ^ difference, right ^ difference];
}
