import { describe, expect, it, vi } from "vitest";
import { hexToBytes, u64be, utf8 } from "./bytes";
import { type SealedIkeMessage, sealIkeEncryptedMessage } from "./ike";
import { IkeMessageSender } from "./ike-iv";
import {
  ExchangeType,
  IKE_FLAG_INITIATOR,
  IKE_FLAG_RESPONSE,
  PayloadType,
  payload,
} from "./ike-wire";

const SPIS = {
  initiatorSpi: hexToBytes("0102030405060708"),
  responderSpi: hexToBytes("1112131415161718"),
};
const KEYMAT = hexToBytes("000102030405060708090a0b0c0d0e0fa0a1a2a3");
const body = (text: string) => [payload(PayloadType.NOTIFY, utf8(text))];

describe("directional IKE explicit-IV allocation", () => {
  it("caches exact retransmission bytes without allocating a second IV", async () => {
    const sender = new IkeMessageSender({
      ...SPIS,
      keyWithSalt: KEYMAT,
      originalSenderIsInitiator: true,
    });
    const request = {
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_INITIATOR,
      messageId: 7,
      innerPayloads: body("delete"),
    };
    const first = await sender.send(request);
    first.message[0] ^= 1;
    const retransmission = await sender.send(request);
    expect(retransmission.explicitIv).toEqual(u64be(1n));
    expect(retransmission.message[0]).toBe(SPIS.initiatorSpi[0]);
    expect(sender.currentIvCounter).toBe(1n);
  });

  it("does not derive the IV from Message ID or conflate request and response", async () => {
    const sender = new IkeMessageSender({
      ...SPIS,
      keyWithSalt: KEYMAT,
      originalSenderIsInitiator: true,
    });
    const request = await sender.send({
      exchangeType: ExchangeType.CREATE_CHILD_SA,
      flags: IKE_FLAG_INITIATOR,
      messageId: 9,
      innerPayloads: body("request"),
    });
    const response = await sender.send({
      exchangeType: ExchangeType.CREATE_CHILD_SA,
      flags: IKE_FLAG_INITIATOR | IKE_FLAG_RESPONSE,
      messageId: 9,
      innerPayloads: body("response"),
    });
    expect(request.explicitIv).toEqual(u64be(1n));
    expect(response.explicitIv).toEqual(u64be(2n));
    expect(response.nonce).not.toEqual(request.nonce);
  });

  it("shares one in-flight encoding for simultaneous retransmission calls", async () => {
    const sealer = vi.fn(
      async (options: Parameters<typeof sealIkeEncryptedMessage>[0]) => {
        await Promise.resolve();
        return sealIkeEncryptedMessage(options);
      },
    );
    const sender = new IkeMessageSender({
      ...SPIS,
      keyWithSalt: KEYMAT,
      originalSenderIsInitiator: false,
      sealer,
    });
    const send = {
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_RESPONSE,
      messageId: 3,
      innerPayloads: body("ack"),
    };
    const [left, right] = await Promise.all([
      sender.send(send),
      sender.send(send),
    ]);
    expect(left.message).toEqual(right.message);
    expect(sealer).toHaveBeenCalledTimes(1);
    expect(sender.currentIvCounter).toBe(1n);
  });

  it("burns a reserved IV after an AEAD failure and validates before allocation", async () => {
    let calls = 0;
    const sealer = async (
      options: Parameters<typeof sealIkeEncryptedMessage>[0],
    ): Promise<SealedIkeMessage> => {
      calls += 1;
      if (calls === 1) throw new Error("synthetic Web Crypto failure");
      return sealIkeEncryptedMessage(options);
    };
    const sender = new IkeMessageSender({
      ...SPIS,
      keyWithSalt: KEYMAT,
      originalSenderIsInitiator: true,
      sealer,
    });
    await expect(
      sender.send({
        exchangeType: ExchangeType.INFORMATIONAL,
        flags: IKE_FLAG_INITIATOR,
        messageId: 1,
        innerPayloads: body("first"),
      }),
    ).rejects.toThrow(/synthetic/);
    expect(sender.currentIvCounter).toBe(1n);

    await expect(
      sender.send({
        exchangeType: 999,
        flags: IKE_FLAG_INITIATOR,
        messageId: 2,
        innerPayloads: body("invalid"),
      }),
    ).rejects.toThrow(/octet/);
    expect(sender.currentIvCounter).toBe(1n);

    const second = await sender.send({
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_INITIATOR,
      messageId: 2,
      innerPayloads: body("second"),
    });
    expect(second.explicitIv).toEqual(u64be(2n));
    expect(sender.currentIvCounter).toBe(2n);
  });

  it("refuses changed content under a cached retransmission identity", async () => {
    const sender = new IkeMessageSender({
      ...SPIS,
      keyWithSalt: KEYMAT,
      originalSenderIsInitiator: true,
    });
    const base = {
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_INITIATOR,
      messageId: 5,
    };
    await sender.send({ ...base, innerPayloads: body("original") });
    await expect(
      sender.send({ ...base, innerPayloads: body("changed") }),
    ).rejects.toThrow(/different protected content/);
    expect(sender.currentIvCounter).toBe(1n);
  });

  it("refuses request Message-ID reuse across exchange types and skipped counters", async () => {
    const sender = new IkeMessageSender({
      ...SPIS,
      keyWithSalt: KEYMAT,
      originalSenderIsInitiator: true,
    });
    await sender.send({
      exchangeType: ExchangeType.INFORMATIONAL,
      flags: IKE_FLAG_INITIATOR,
      messageId: 4,
      innerPayloads: body("first request"),
    });
    await expect(
      sender.send({
        exchangeType: ExchangeType.CREATE_CHILD_SA,
        flags: IKE_FLAG_INITIATOR,
        messageId: 4,
        innerPayloads: body("reused as another exchange"),
      }),
    ).rejects.toThrow(/different protected content/);
    await expect(
      sender.send({
        exchangeType: ExchangeType.INFORMATIONAL,
        flags: IKE_FLAG_INITIATOR,
        messageId: 6,
        innerPayloads: body("skipped five"),
      }),
    ).rejects.toThrow(/advance.*5/);
    expect(sender.currentIvCounter).toBe(1n);
  });
});
