# E-K-03 implementation brief

## Claim

This lesson executes a bounded IKEv2/ESP profile from policy decision through protected packet reception and Child-SA rekeying. It makes wire-format and state-machine claims only for the profile below. It does not claim interoperability, production hardening or security for omitted IKE/IPsec features.

## Source-to-code map

| Behavior                                                                                                                       | Primary source                             | Implementation                      |
| ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------ | ----------------------------------- |
| Ordered SPD and separate routing/SAD concepts                                                                                  | RFC 4301 §§4.4, 5                          | `src/protocol/spd.ts`               |
| IKE header, payload chains, proposals, first Child SA in IKE_AUTH, PSK AUTH, key derivation, Message IDs and traffic selectors | RFC 7296 §§1.2–1.4, 2.2, 2.9, 2.13–2.17, 3 | `ike-wire.ts`, `ike.ts`, `rekey.ts` |
| Curve25519 KE payload encoding and direct little-endian X25519 result                                                          | RFC 8031 §§2–3 and Appendix A              | `x25519.ts`, `ike-wire.ts`          |
| X25519 masking, non-canonical input handling and optional all-zero check                                                       | RFC 7748 §§5, 6                            | `x25519.ts`                         |
| AES-GCM IKE key sizes, nonce, AAD, encrypted-payload padding and tag                                                           | RFC 5282 §§3–7                             | `ike.ts`, `ike-iv.ts`               |
| ESP packet, padding/trailer, inbound processing, replay and sequence limits                                                    | RFC 4303 §§2–3                             | `esp.ts`, `ipv4.ts`                 |
| AES-GCM ESP key/salt, nonce and AAD                                                                                            | RFC 4106 §§3–7                             | `esp.ts`                            |
| Transport request/echo/fallback                                                                                                | RFC 7296 §1.3.1                            | `ike.ts`, `rekey.ts`                |
| Child-SA rekey, overlap, REKEY_SA and Delete                                                                                   | RFC 7296 §§1.3.3, 1.4.1, 2.8, 3.11         | `rekey.ts`, `lab.ts`                |

## Exact profile

The IKE proposal carries AES-GCM-16 transform 20 with key-length attribute 128, PRF HMAC-SHA2-256 transform 5, and Key Exchange Method 31. It omits an INTEG transform because AES-GCM is AEAD. The first Child-SA proposal carries ESP protocol 3, the same encryption transform/key length, and sequence-numbers transform type 5 ID 0; it omits KE and INTEG.

The 136-byte IKE key stream is split into 32-byte `SK_d`, zero bytes each for `SK_ai` and `SK_ar`, 20 bytes each for `SK_ei` and `SK_er`, and 32 bytes each for `SK_pi` and `SK_pr`. Each 20-byte AEAD key material value is a 16-byte AES key followed by a four-byte salt. Initial Child KEYMAT is exactly 40 bytes from `prf+(SK_d, Ni | Nr)`, split in current Child-exchange initiator-to-responder order.

IKE encrypted-payload AAD is the 28-byte IKE header plus the four-byte SK header. Its plaintext is the inner payload chain, optional teaching-profile padding, and one Pad Length byte; it does not use the ESP Next Header trailer. One monotonic 64-bit explicit-IV allocator exists per IKE sending direction, independent of Message IDs. It burns an IV before calling AEAD and caches a successful message’s exact bytes for retransmission.

ESP AAD is `SPI | sequence`; its nonce is the four-byte salt plus the demo’s eight-byte big-endian sequence-derived explicit IV. Plaintext is payload, canonical minimal padding, Pad Length and Next Header. Sender state begins at zero, emits one first, permits `0xffffffff`, and refuses another packet before wrap. The receiver performs SAD lookup, pure replay precheck, AES-GCM authentication, replay commit, and trailer validation; therefore an invalid tag never moves the window, while an authenticated malformed trailer consumes its sequence without releasing plaintext.

## Vector provenance

- X25519 tests pin RFC 7748 §6.1 and RFC 8031 Appendix A, including RFC 8031 masking/non-canonical-input behavior.
- HMAC-SHA-256 pins RFC 4231 test case 1 (also reproduced in RFC 4868 §2.7.1).
- AES-GCM pins the published GCM Test Case 4 referenced by RFC 4106 §9 and an independent Node computation.
- The complete IKE transcript, PSK, identities, SPIs, selectors and exact ESP packet are project-owned fixtures, not mislabeled RFC vectors. Tests recompute every fixture with Web Crypto and independently cross-check the transmitted IKE_AUTH messages and exact ESP packet with Node's cryptographic implementation.

## Required negative evidence

Tests cover altered transcript, identity and transmitted AUTH; IKE-versus-ESP AAD; wrong directional KEYMAT/SPI interpretation; non-canonical and all-zero X25519 inputs; IKE and ESP IV burn on AEAD failure; duplicate, too-old, unknown-SPI and invalid-tag replay cases; malformed authenticated trailers; transport echo/fallback; responder-initiated Message-ID and selector roles; fresh rekey SPI/key/state separation; protected paired-SPI Delete; and sequence exhaustion before wrap.

## Retained limits

The browser executes no UDP socket, daemon, certificate path, EAP exchange, IPv6, NAT traversal, fragmentation, MOBIKE, IKE-SA rekey, AH, multicast, ESN, multiple-proposal negotiation, kernel policy install or production secret storage. The hand-written BigInt X25519 ladder is independently vector-tested teaching arithmetic, not a constant-time production implementation. Traffic selectors contain one IPv4 range each. Rekey is Child-SA rekey without a fresh DH transform. The deterministic button is evidence infrastructure; fresh learner runs use new entropy.
