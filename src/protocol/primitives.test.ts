import { createCipheriv, createDecipheriv, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bytesToHex, concatBytes, hexToBytes, utf8 } from "./bytes";
import { aesGcmOpen, aesGcmSeal, hmacSha256, sha256 } from "./primitives";

describe("cryptographic primitive wrappers", () => {
  it("matches RFC 4231 HMAC-SHA-256 test case 1", async () => {
    const key = new Uint8Array(20).fill(0x0b);
    expect(bytesToHex(await hmacSha256(key, utf8("Hi There")))).toBe(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
  });

  it("matches an independent Node HMAC computation", async () => {
    const key = hexToBytes("00112233445566778899aabbccddeeff");
    const data = utf8("IKEv2 key schedule");
    const expected = createHmac("sha256", key).update(data).digest("hex");
    expect(bytesToHex(await hmacSha256(key, data))).toBe(expected);
  });

  it("matches the SHA-256 abc vector", async () => {
    expect(bytesToHex(await sha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("seals exact AES-GCM bytes and opens them", async () => {
    const key = hexToBytes("00000000000000000000000000000000");
    const nonce = hexToBytes("000000000000000000000000");
    const plaintext = hexToBytes("00000000000000000000000000000000");
    const sealed = await aesGcmSeal(key, nonce, plaintext, new Uint8Array());
    expect(bytesToHex(concatBytes(sealed.ciphertext, sealed.tag))).toBe(
      "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
    );
    expect(
      await aesGcmOpen(
        key,
        nonce,
        sealed.ciphertext,
        sealed.tag,
        new Uint8Array(),
      ),
    ).toEqual(plaintext);
  });

  it("matches published AES-GCM Test Case 4 with nonempty AAD", async () => {
    const key = hexToBytes("feffe9928665731c6d6a8f9467308308");
    const nonce = hexToBytes("cafebabefacedbaddecaf888");
    const aad = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const plaintext = hexToBytes(
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a7" +
        "21c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    );
    const sealed = await aesGcmSeal(key, nonce, plaintext, aad);
    expect(bytesToHex(sealed.ciphertext)).toBe(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
    );
    expect(bytesToHex(sealed.tag)).toBe("5bc94fbc3221a5db94fae95ae7121a47");
    expect(
      await aesGcmOpen(key, nonce, sealed.ciphertext, sealed.tag, aad),
    ).toEqual(plaintext);
  });

  it("agrees with Node AES-GCM when AAD is present", async () => {
    const key = hexToBytes("feffe9928665731c6d6a8f9467308308");
    const nonce = hexToBytes("cafebabefacedbaddecaf888");
    const plaintext = utf8("authenticated IKE and ESP bytes");
    const aad = hexToBytes("0102030405060708");
    const ours = await aesGcmSeal(key, nonce, plaintext, aad);
    const reference = createCipheriv("aes-128-gcm", key, nonce);
    reference.setAAD(aad);
    const ciphertext = Buffer.concat([
      reference.update(plaintext),
      reference.final(),
    ]);
    expect(ours.ciphertext).toEqual(new Uint8Array(ciphertext));
    expect(ours.tag).toEqual(new Uint8Array(reference.getAuthTag()));

    const decipher = createDecipheriv("aes-128-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(ours.tag);
    const opened = Buffer.concat([
      decipher.update(ours.ciphertext),
      decipher.final(),
    ]);
    expect(new Uint8Array(opened)).toEqual(plaintext);
  });

  it("snapshots caller-owned HMAC and AEAD bytes before the first await", async () => {
    const hmacKey = hexToBytes("00112233445566778899aabbccddeeff");
    const hmacData = utf8("snapshot this HMAC input");
    const expectedHmac = createHmac("sha256", hmacKey.slice())
      .update(hmacData.slice())
      .digest("hex");
    const pendingHmac = hmacSha256(hmacKey, hmacData);
    hmacKey.fill(0xff);
    hmacData.fill(0xff);
    expect(bytesToHex(await pendingHmac)).toBe(expectedHmac);

    const key = hexToBytes("feffe9928665731c6d6a8f9467308308");
    const nonce = hexToBytes("cafebabefacedbaddecaf888");
    const plaintext = utf8("snapshot this AEAD input");
    const aad = hexToBytes("0102030405060708");
    const expectedPlaintext = plaintext.slice();
    const expected = await aesGcmSeal(
      key.slice(),
      nonce.slice(),
      expectedPlaintext,
      aad.slice(),
    );
    const pendingSeal = aesGcmSeal(key, nonce, plaintext, aad);
    key.fill(0xff);
    nonce.fill(0xff);
    plaintext.fill(0xff);
    aad.fill(0xff);
    const sealed = await pendingSeal;
    expect(sealed).toEqual(expected);

    const openKey = hexToBytes("feffe9928665731c6d6a8f9467308308");
    const openNonce = hexToBytes("cafebabefacedbaddecaf888");
    const openCiphertext = sealed.ciphertext.slice();
    const openTag = sealed.tag.slice();
    const openAad = hexToBytes("0102030405060708");
    const pendingOpen = aesGcmOpen(
      openKey,
      openNonce,
      openCiphertext,
      openTag,
      openAad,
    );
    openKey.fill(0xff);
    openNonce.fill(0xff);
    openCiphertext.fill(0xff);
    openTag.fill(0xff);
    openAad.fill(0xff);
    expect(await pendingOpen).toEqual(expectedPlaintext);
  });

  it("rejects altered ciphertext, AAD, tag, key, and nonce lengths", async () => {
    const key = new Uint8Array(16);
    const nonce = new Uint8Array(12);
    const sealed = await aesGcmSeal(
      key,
      nonce,
      utf8("payload"),
      Uint8Array.of(1),
    );
    const changed = sealed.ciphertext.slice();
    changed[0] ^= 1;
    await expect(
      aesGcmOpen(key, nonce, changed, sealed.tag, Uint8Array.of(1)),
    ).rejects.toThrow(/authentication/);
    await expect(
      aesGcmOpen(key, nonce, sealed.ciphertext, sealed.tag, Uint8Array.of(2)),
    ).rejects.toThrow(/authentication/);
    await expect(
      aesGcmOpen(
        new Uint8Array(15),
        nonce,
        sealed.ciphertext,
        sealed.tag,
        Uint8Array.of(1),
      ),
    ).rejects.toThrow(/key/);
  });
});
