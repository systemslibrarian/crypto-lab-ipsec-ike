import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "./bytes";
import {
  decodeUCoordinate,
  x25519,
  x25519PublicKey,
  x25519WithPolicy,
} from "./x25519";

const ALICE_PRIVATE = hexToBytes(
  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
);
const ALICE_PUBLIC =
  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_PRIVATE = hexToBytes(
  "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
);
const BOB_PUBLIC =
  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const SHARED =
  "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

describe("RFC 7748 X25519", () => {
  it("matches the published Alice and Bob vector", () => {
    expect(bytesToHex(x25519PublicKey(ALICE_PRIVATE))).toBe(ALICE_PUBLIC);
    expect(bytesToHex(x25519PublicKey(BOB_PRIVATE))).toBe(BOB_PUBLIC);
    expect(bytesToHex(x25519(ALICE_PRIVATE, hexToBytes(BOB_PUBLIC)))).toBe(
      SHARED,
    );
    expect(bytesToHex(x25519(BOB_PRIVATE, hexToBytes(ALICE_PUBLIC)))).toBe(
      SHARED,
    );
  });

  it("masks the input top bit as required", () => {
    const canonical = hexToBytes(BOB_PUBLIC);
    const highBitSet = canonical.slice();
    highBitSet[31] = highBitSet[31]! | 0x80;
    const result = x25519WithPolicy(ALICE_PRIVATE, highBitSet);
    expect(result.maskedTopBit).toBe(true);
    expect(bytesToHex(result.sharedSecret)).toBe(SHARED);
  });

  it("accepts and reduces a non-canonical field encoding", () => {
    // p + 9 = 2^255 - 10, encoded little-endian. It represents base point 9.
    const nonCanonical = hexToBytes(
      "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    );
    const decoded = decodeUCoordinate(nonCanonical);
    expect(decoded.nonCanonical).toBe(true);
    expect(decoded.value).toBe(9n);
    expect(x25519(ALICE_PRIVATE, nonCanonical)).toEqual(
      x25519PublicKey(ALICE_PRIVATE),
    );
  });

  it("keeps optional all-zero refusal separate from X25519 decoding", () => {
    const zero = new Uint8Array(32);
    const accepted = x25519WithPolicy(ALICE_PRIVATE, zero);
    expect(accepted.allZero).toBe(true);
    expect(() =>
      x25519WithPolicy(ALICE_PRIVATE, zero, { rejectAllZero: true }),
    ).toThrow(/local policy/i);
  });

  it("refuses wrong-length inputs", () => {
    expect(() => x25519(new Uint8Array(31), new Uint8Array(32))).toThrow(
      /scalar/,
    );
    expect(() => x25519(new Uint8Array(32), new Uint8Array(31))).toThrow(
      /u-coordinate/,
    );
  });
});

describe("RFC 8031 Appendix A Curve25519-for-IKE vector", () => {
  it("reproduces both public values and the direct 32-octet shared secret", () => {
    const initiatorPrivate = hexToBytes(
      "751fb4308655b476b6789b7325f9ea8cddd16a58533ff6d9e60009464a5f9d94",
    );
    const responderPrivate = hexToBytes(
      "0a54645253290d60ddadd0e030bacd9e5501efdc220755a1e978f1b839a05688",
    );
    const initiatorPublic =
      "48d5ddd4061257ba166fa3f9bbdb74f1a4e81c089384fa77f790709f0dfbc766";
    const responderPublic =
      "0be7c1f5aad87d7e448662673298a443478b859745179eaf564c79c0ef6eee25";
    const shared =
      "c74950607a12327f3204d94b6825bfb068b7f8319a9e3708ed3d43ce8130c950";
    expect(bytesToHex(x25519PublicKey(initiatorPrivate))).toBe(initiatorPublic);
    expect(bytesToHex(x25519PublicKey(responderPrivate))).toBe(responderPublic);
    expect(
      bytesToHex(x25519(initiatorPrivate, hexToBytes(responderPublic))),
    ).toBe(shared);
    expect(
      bytesToHex(x25519(responderPrivate, hexToBytes(initiatorPublic))),
    ).toBe(shared);
  });
});
