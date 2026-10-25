import { concatBytes, requireLength } from "./bytes";

const GCM_TAG_BYTES = 16;

export interface AeadSealed {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/**
 * Web Crypto's TypeScript surface accepts only ArrayBuffer-backed views. Copy
 * caller-owned bytes so SharedArrayBuffer-backed inputs cannot cross that API
 * boundary and so an asynchronous operation cannot observe later mutation.
 */
function cryptoBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(bytes);
}

export async function hmacSha256(
  keyBytes: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const keyInput = cryptoBytes(keyBytes);
  const dataInput = cryptoBytes(data);
  if (keyInput.length === 0)
    throw new RangeError("HMAC key must not be empty.");
  const key = await crypto.subtle.importKey(
    "raw",
    keyInput,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, dataInput));
}

export async function sha256(
  data: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", cryptoBytes(data)),
  );
}

export async function aesGcmSeal(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array,
): Promise<AeadSealed> {
  const keyInput = cryptoBytes(keyBytes);
  const nonceInput = cryptoBytes(nonce);
  const plaintextInput = cryptoBytes(plaintext);
  const additionalDataInput = cryptoBytes(additionalData);
  requireLength(keyInput, 16, "AES-128-GCM key");
  requireLength(nonceInput, 12, "AES-GCM nonce");
  const key = await crypto.subtle.importKey("raw", keyInput, "AES-GCM", false, [
    "encrypt",
  ]);
  const combined = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonceInput,
        additionalData: additionalDataInput,
        tagLength: 128,
      },
      key,
      plaintextInput,
    ),
  );
  return {
    ciphertext: combined.slice(0, -GCM_TAG_BYTES),
    tag: combined.slice(-GCM_TAG_BYTES),
  };
}

export async function aesGcmOpen(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  const keyInput = cryptoBytes(keyBytes);
  const nonceInput = cryptoBytes(nonce);
  const ciphertextInput = cryptoBytes(ciphertext);
  const tagInput = cryptoBytes(tag);
  const additionalDataInput = cryptoBytes(additionalData);
  requireLength(keyInput, 16, "AES-128-GCM key");
  requireLength(nonceInput, 12, "AES-GCM nonce");
  requireLength(tagInput, GCM_TAG_BYTES, "AES-GCM tag");
  const key = await crypto.subtle.importKey("raw", keyInput, "AES-GCM", false, [
    "decrypt",
  ]);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonceInput,
          additionalData: additionalDataInput,
          tagLength: 128,
        },
        key,
        cryptoBytes(concatBytes(ciphertextInput, tagInput)),
      ),
    );
  } catch {
    throw new Error("AES-GCM authentication failed.");
  }
}
