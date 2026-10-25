# IPsec / IKE — Crypto Lab

[Live Demo](https://systemslibrarian.github.io/crypto-lab-ipsec-ike/)

## What It Is

This lab is a bounded, executable IKEv2 and ESP packet-flow lesson. It applies an ordered Security Policy Database, performs a real four-message PSK IKEv2 setup with X25519, derives two unidirectional Child-SA key streams, and protects actual IPv4 bytes with AES-GCM-16/128. The receiver performs SAD lookup, a non-mutating 64-packet replay precheck, authentication, replay-state commit, trailer validation, packet reconstruction, and checksum verification in that order. Separate cases execute transport negotiation, tunnel fallback, protected Child-SA deletion, valid reordering, replay, too-old and invalid-tag handling, and fresh-state Child-SA rekeying. It is deliberately not an interoperable VPN daemon or production credential store.

## When to Use It

- Use it to trace where IPsec policy ends and route selection begins, because the three SPD dispositions and the route are computed separately.
- Use it to inspect IKEv2 and ESP bytes, keys, nonces, AAD and state transitions, because every displayed outcome is derived from the current browser run.
- Use it for testing replay, mode-fallback and Child-SA rekey reasoning, because the negative cases exercise the same packet receiver and state as the honest path.
- Do not use it to protect real traffic or select deployment algorithms, because it is a demo app and does not provide hardened operational controls.

## Declared teaching profile

- IPv4 TEST-NET fixtures; no network packets leave the browser.
- IKEv2 PSK AUTH method 2, Curve25519 Key Exchange Method 31 computed with X25519, PRF_HMAC_SHA2_256 transform 5, and ENCR_AES_GCM_16 transform 20 with a 128-bit key attribute.
- AEAD-only IKE key split: zero-length `SK_ai`/`SK_ar`, 20-byte `SK_ei`/`SK_er` values (16-byte AES key plus four-byte salt).
- Initial Child SA established inside IKE_AUTH with no KE or INTEG transform; `KEYMAT = prf+(SK_d, Ni | Nr)`.
- ESP transform 20, sequence-numbers transform 0, a 16-byte tag, minimal default padding, and a 64-packet replay window.
- Separate per-direction IKE IV allocators and ESP sequence/IV allocators burn state before AEAD and cache exact successful IKE retransmissions.

Fresh learner runs generate new X25519 private scalars, nonces, IKE SPIs, Child-SA SPIs and a binary teaching PSK with Web Crypto. The “Load fixed evidence” control is the only deterministic application seam. It pins published RFC 8031 X25519 inputs plus project-owned IKE and ESP transcript oracles independently recomputed with Node’s cryptographic implementation in tests.

## Run locally

Requires Node.js 22.13.x, an even-numbered Node.js release from 24 onward, or Node.js 26+.

```sh
npm ci
npm run dev
```

The complete local gate is:

```sh
npm run format:check
npm run typecheck
npm run lint
npm run test:coverage
npm run build
npm run test:e2e
npm run test:mutations
```

## Security boundaries

The lesson excludes certificates, EAP, IPv6, NAT traversal, fragmentation, MOBIKE, multiple proposals, AH, multicast, traffic-flow-confidentiality padding, extended sequence numbers, kernel routing and production secret storage. Its sequence-derived ESP explicit IV is a declared uniqueness construction for this profile, not an IKE-negotiated universal algorithm. Its hand-written BigInt X25519 ladder is testable teaching arithmetic, not constant-time production code. Rejecting an all-zero X25519 shared result is the demo’s optional RFC 7748 local policy; it is not presented as an RFC 8031 MUST. Registered algorithm requirement levels describe implementation support and are not universal deployment recommendations.

See [the implementation brief](docs/e-k-03-brief.md) for exact source sections, wire choices, vector provenance and retained limits.

## Primary references

- [RFC 4301 — Security Architecture for IP](https://www.rfc-editor.org/rfc/rfc4301.html)
- [RFC 4303 — Encapsulating Security Payload](https://www.rfc-editor.org/rfc/rfc4303.html)
- [RFC 4106 — AES-GCM for ESP](https://www.rfc-editor.org/rfc/rfc4106.html)
- [RFC 5282 — AEAD algorithms for IKEv2](https://www.rfc-editor.org/rfc/rfc5282.html)
- [RFC 7296 — IKEv2](https://www.rfc-editor.org/rfc/rfc7296.html)
- [RFC 7748 — X25519 and X448](https://www.rfc-editor.org/rfc/rfc7748.html)
- [RFC 8031 — Curve25519 and Curve448 for IKEv2](https://www.rfc-editor.org/rfc/rfc8031.html)
- [RFC 8221 — ESP and AH algorithm requirements](https://www.rfc-editor.org/rfc/rfc8221.html)
- [RFC 8247 — IKEv2 algorithm requirements](https://www.rfc-editor.org/rfc/rfc8247.html)
- [RFC 9370 — IKEv2 key-exchange terminology](https://www.rfc-editor.org/rfc/rfc9370.html)
- [RFC 9827 — IKEv2 sequence-number transform terminology](https://www.rfc-editor.org/rfc/rfc9827.html)
- [IANA IKEv2 Parameters](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml)

## License

[MIT](LICENSE)
