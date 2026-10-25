import { hexToBytes, ipv4ToBytes } from "./bytes";
import type { HandshakeInputs } from "./ike";
import { addressRange, anyPort } from "./spd";

/**
 * Deterministic project fixture. Its X25519 inputs are RFC 8031 Appendix A;
 * its IKE transcript, PSK, identities, selectors, SPIs, and IVs are explicitly
 * project-owned test data rather than an RFC transcript vector.
 */
export function fixedHandshakeInputs(): HandshakeInputs {
  const selector = {
    sourceAddress: addressRange("192.0.2.10"),
    destinationAddress: addressRange("198.51.100.20"),
    sourcePort: anyPort(),
    destinationPort: anyPort(),
    protocol: 1,
  };
  return {
    initiatorPrivate: hexToBytes(
      "751fb4308655b476b6789b7325f9ea8cddd16a58533ff6d9e60009464a5f9d94",
    ),
    responderPrivate: hexToBytes(
      "0a54645253290d60ddadd0e030bacd9e5501efdc220755a1e978f1b839a05688",
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
    psk: hexToBytes(
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
    ),
    initiatorIdentity: {
      type: 1,
      data: ipv4ToBytes("192.0.2.10"),
      label: "192.0.2.10",
    },
    responderIdentity: {
      type: 1,
      data: ipv4ToBytes("198.51.100.20"),
      label: "198.51.100.20",
    },
    offeredSelector: selector,
    responderPolicy: selector,
    requestedMode: "tunnel",
    responderAllowsTransport: false,
    initiatorAcceptsTunnelFallback: true,
    rejectAllZeroDh: true,
  };
}

export const FIXED_EXPECTED = {
  initiatorPublic:
    "48d5ddd4061257ba166fa3f9bbdb74f1a4e81c089384fa77f790709f0dfbc766",
  responderPublic:
    "0be7c1f5aad87d7e448662673298a443478b859745179eaf564c79c0ef6eee25",
  sharedSecret:
    "c74950607a12327f3204d94b6825bfb068b7f8319a9e3708ed3d43ce8130c950",
  skeyseed: "57537a70ced6a4abd62b10ac224bedc279492add0ce9fb31634fcdc67f9f91a6",
  skD: "b2ac2c6acb547f1ab2a5989f9cc32c70b5939328ea1322d027a2b83013fa767e",
  skEi: "cc3d09e570eea6f5febe1f6714da80f95c5c7b5a",
  skEr: "b9e0ee9bee09442cb4ba7e577d6f9696c77af114",
  skPi: "ac718fc1e6f969296872d81a6cb260767c71bf5e99a0600aeb9ac88299f1b225",
  skPr: "7a0f5ff057659139dd75b22a2ccba10c8cba74cbc9d1b453be2ad1af27720200",
  authI: "64cd35f25e5a0aaa201ab012ea7b1bdd43ed8831bb94cc63e6985f3e52adaba5",
  authR: "0ff29a63f43b1d654788649a9899ef8c6d5da88f6770edfeb3c33cdef486ba8f",
  childI2R: "1d6cf73928562f348b2e49a0bf6a8be42d22d264",
  childR2I: "50d04acdc035cb6c5d1f9134dbe21e47fd7f0402",
  initRequestSha256:
    "531c9a3f43a8d0d6dc6b6ff65d6a1c210968df1afde0a25986e98ed2eaa3ca73",
  initResponseSha256:
    "3e10428606255a818251658d6dd3e82bf3ffce6c8ffefa13d4727daf71b8f5d9",
  authRequestSha256:
    "64e43e2a17e575c7ff9ee38b37313bd893c6016dffde11cdf246a2b62cf4774e",
  authResponseSha256:
    "a525495a6d508aa2a80028cec6d7d27a869927b11925dc4f127f1cde4e8d35b5",
} as const;
