import { describe, expect, it } from "vitest";
import {
  bytesEqual,
  bytesToHex,
  bytesToIpv4,
  concatBytes,
  hexToBytes,
  ipv4ToBytes,
  ipv4ToNumber,
  readU16be,
  readU32be,
  readU64be,
  requireLength,
  u16be,
  u32be,
  u64be,
} from "./bytes";

describe("byte encodings", () => {
  it("round-trips strict hex and concatenates without aliasing", () => {
    const left = hexToBytes("00 aa ff");
    const joined = concatBytes(left, Uint8Array.of(1, 2));
    left[0] = 9;
    expect(bytesToHex(joined)).toBe("00aaff0102");
    expect(hexToBytes(bytesToHex(joined))).toEqual(joined);
  });

  it.each(["0", "0g", "-1", "abc_"])("rejects malformed hex %s", (value) => {
    expect(() => hexToBytes(value)).toThrow(/hex/i);
  });

  it("encodes and reads unsigned network-order integers", () => {
    expect(readU16be(u16be(0xcafe))).toBe(0xcafe);
    expect(readU32be(u32be(0xfedcba98))).toBe(0xfedcba98);
    expect(readU64be(u64be(0x0123456789abcdefn))).toBe(0x0123456789abcdefn);
  });

  it("checks integer and slice bounds", () => {
    expect(() => u16be(-1)).toThrow(RangeError);
    expect(() => u32be(0x1_0000_0000)).toThrow(RangeError);
    expect(() => u64be(0x1_0000_0000_0000_0000n)).toThrow(RangeError);
    expect(() => readU32be(Uint8Array.of(1, 2, 3))).toThrow(RangeError);
  });

  it("parses canonical IPv4 addresses", () => {
    expect(ipv4ToBytes("192.0.2.9")).toEqual(Uint8Array.of(192, 0, 2, 9));
    expect(bytesToIpv4(Uint8Array.of(198, 51, 100, 8))).toBe("198.51.100.8");
    expect(ipv4ToNumber("203.0.113.1")).toBe(0xcb007101);
    for (const invalid of ["192.0.2", "192.0.2.256", "192.00.2.1", "x.0.2.1"]) {
      expect(() => ipv4ToBytes(invalid)).toThrow(/IPv4/);
    }
  });

  it("compares all bytes and enforces exact lengths", () => {
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1), Uint8Array.of(1, 0))).toBe(false);
    expect(requireLength(Uint8Array.of(1), 1, "fixture")).toEqual(
      Uint8Array.of(1),
    );
    expect(() => requireLength(Uint8Array.of(1), 2, "fixture")).toThrow(
      /fixture/,
    );
  });
});
