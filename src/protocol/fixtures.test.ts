import { createCipheriv, createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bytesToHex, concatBytes, hexToBytes } from "./bytes";
import { EspSender, createEspSa } from "./esp";
import { FIXED_EXPECTED, fixedHandshakeInputs } from "./fixtures";
import { runIkeHandshake } from "./ike";
import { sha256 } from "./primitives";
import { IP_PROTOCOL_IPV4, buildIpv4Packet } from "./ipv4";

describe("fixed IKE project fixture", () => {
  it("pins the published RFC 8031 X25519 inputs and results", async () => {
    const result = await runIkeHandshake(fixedHandshakeInputs());
    expect(bytesToHex(result.initiatorPublic)).toBe(
      FIXED_EXPECTED.initiatorPublic,
    );
    expect(bytesToHex(result.responderPublic)).toBe(
      FIXED_EXPECTED.responderPublic,
    );
    expect(bytesToHex(result.initiatorDh.sharedSecret)).toBe(
      FIXED_EXPECTED.sharedSecret,
    );
    expect(result.responderDh.sharedSecret).toEqual(
      result.initiatorDh.sharedSecret,
    );
  });

  it("pins independently recomputed project key and AUTH values", async () => {
    const result = await runIkeHandshake(fixedHandshakeInputs());
    expect(bytesToHex(result.keys.skeyseed)).toBe(FIXED_EXPECTED.skeyseed);
    expect(bytesToHex(result.keys.skD)).toBe(FIXED_EXPECTED.skD);
    expect(bytesToHex(result.keys.skEi)).toBe(FIXED_EXPECTED.skEi);
    expect(bytesToHex(result.keys.skEr)).toBe(FIXED_EXPECTED.skEr);
    expect(bytesToHex(result.keys.skPi)).toBe(FIXED_EXPECTED.skPi);
    expect(bytesToHex(result.keys.skPr)).toBe(FIXED_EXPECTED.skPr);
    expect(bytesToHex(result.initiatorAuth)).toBe(FIXED_EXPECTED.authI);
    expect(bytesToHex(result.responderAuth)).toBe(FIXED_EXPECTED.authR);
    expect(bytesToHex(result.childKeys.initiatorToResponder)).toBe(
      FIXED_EXPECTED.childI2R,
    );
    expect(bytesToHex(result.childKeys.responderToInitiator)).toBe(
      FIXED_EXPECTED.childR2I,
    );
  });

  it("pins exact complete transcript lengths and project SHA-256 oracles", async () => {
    const result = await runIkeHandshake(fixedHandshakeInputs());
    expect(result.ikeSaInitRequest).toHaveLength(144);
    expect(result.ikeSaInitResponse).toHaveLength(144);
    expect(result.ikeAuthRequest.message).toHaveLength(193);
    expect(result.ikeAuthResponse.message).toHaveLength(193);
    expect(bytesToHex(await sha256(result.ikeSaInitRequest))).toBe(
      FIXED_EXPECTED.initRequestSha256,
    );
    expect(bytesToHex(await sha256(result.ikeSaInitResponse))).toBe(
      FIXED_EXPECTED.initResponseSha256,
    );
    expect(bytesToHex(await sha256(result.ikeAuthRequest.message))).toBe(
      FIXED_EXPECTED.authRequestSha256,
    );
    expect(bytesToHex(await sha256(result.ikeAuthResponse.message))).toBe(
      FIXED_EXPECTED.authResponseSha256,
    );
    expect(
      createHash("sha256").update(result.ikeAuthRequest.message).digest("hex"),
    ).toBe(FIXED_EXPECTED.authRequestSha256);
    expect(
      createHash("sha256").update(result.ikeAuthResponse.message).digest("hex"),
    ).toBe(FIXED_EXPECTED.authResponseSha256);
  });

  it("matches an independent Node AES-GCM computation for both encrypted messages", async () => {
    const result = await runIkeHandshake(fixedHandshakeInputs());
    for (const [sealed, keymat] of [
      [result.ikeAuthRequest, result.keys.skEi],
      [result.ikeAuthResponse, result.keys.skEr],
    ] as const) {
      const cipher = createCipheriv(
        "aes-128-gcm",
        keymat.slice(0, 16),
        sealed.nonce,
      );
      cipher.setAAD(sealed.aad);
      const ciphertext = Buffer.concat([
        cipher.update(sealed.plaintext),
        cipher.final(),
      ]);
      expect(new Uint8Array(ciphertext)).toEqual(sealed.ciphertext);
      expect(new Uint8Array(cipher.getAuthTag())).toEqual(sealed.tag);
      expect(sealed.message).toEqual(
        concatBytes(
          sealed.aad,
          sealed.explicitIv,
          sealed.ciphertext,
          sealed.tag,
        ),
      );
    }
  });

  it("pins the independently recomputed end-to-end project ESP packet", async () => {
    const result = await runIkeHandshake(fixedHandshakeInputs());
    const inner = buildIpv4Packet({
      source: "192.0.2.10",
      destination: "198.51.100.20",
      protocol: 1,
      identification: 0x4242,
      payload: hexToBytes("0800e4a91234000163727970746f2d6c616221"),
    });
    expect(bytesToHex(inner.bytes)).toBe(
      "450000274242400040010c42c000020ac63364140800e4a91234000163727970746f2d6c616221",
    );
    const outbound = createEspSa({
      spi: 0xb1b2b3b4,
      keyWithSalt: result.childKeys.initiatorToResponder,
      direction: "initiator-to-responder",
    });
    const sealed = await new EspSender(outbound).send(
      inner.bytes,
      IP_PROTOCOL_IPV4,
    );
    const expectedPacket =
      "b1b2b3b4000000010000000000000001" +
      "580630fd7557ffc7e624f67db15b392bf56d45936f66274c66b6511b4b1ed025" +
      "244ba9fff622d4f3b2a8a623" +
      "c0b3b04eb51b64e4095fb0e3d28b12f4";
    expect(bytesToHex(sealed.packet)).toBe(expectedPacket);
    expect(createHash("sha256").update(sealed.packet).digest("hex")).toBe(
      "99d2f0e5fd6177f26a20e2e8df15ede721ab51801ea434a4a98b0876887c8239",
    );

    const reference = createCipheriv(
      "aes-128-gcm",
      result.childKeys.initiatorToResponder.slice(0, 16),
      sealed.nonce,
    );
    reference.setAAD(sealed.aad);
    const ciphertext = Buffer.concat([
      reference.update(sealed.plaintext),
      reference.final(),
    ]);
    expect(Uint8Array.from(ciphertext)).toEqual(sealed.ciphertext);
    expect(Uint8Array.from(reference.getAuthTag())).toEqual(sealed.tag);
  });
});
