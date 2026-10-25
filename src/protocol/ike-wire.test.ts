import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes, readU16be, readU32be, utf8 } from "./bytes";
import {
  ExchangeType,
  IKE_FLAG_INITIATOR,
  PayloadType,
  USE_TRANSPORT_MODE,
  childSaProposal,
  decodePayloadChain,
  decodeSingleTsBody,
  encodeAuthBody,
  encodeIdBody,
  encodeIkeMessage,
  encodeKeBody,
  encodeNotifyBody,
  encodePayloadChain,
  encodeSaBody,
  encodeTsBody,
  ikeSaProposal,
  parseIkeHeader,
  payload,
} from "./ike-wire";
import { addressRange, anyPort, portRange, type TrafficSelector } from "./spd";

const SPI_I = hexToBytes("0102030405060708");
const SPI_R = hexToBytes("1112131415161718");

describe("IKEv2 wire encoding", () => {
  it("encodes and parses an IKE_SA_INIT message with exact header length", () => {
    const message = encodeIkeMessage({
      initiatorSpi: SPI_I,
      responderSpi: new Uint8Array(8),
      exchangeType: ExchangeType.IKE_SA_INIT,
      flags: IKE_FLAG_INITIATOR,
      messageId: 0,
      payloads: [
        payload(PayloadType.SA, encodeSaBody([ikeSaProposal()])),
        payload(PayloadType.KE, encodeKeBody(31, new Uint8Array(32).fill(7))),
        payload(PayloadType.NONCE, new Uint8Array(32).fill(9)),
      ],
    });
    const header = parseIkeHeader(message);
    expect(header.initiatorSpi).toEqual(SPI_I);
    expect(header.responderSpi).toEqual(new Uint8Array(8));
    expect(header.nextPayload).toBe(PayloadType.SA);
    expect(header.exchangeType).toBe(ExchangeType.IKE_SA_INIT);
    expect(header.flags).toBe(IKE_FLAG_INITIATOR);
    expect(header.messageId).toBe(0);
    expect(header.length).toBe(message.length);

    const decoded = decodePayloadChain(message.slice(28), header.nextPayload);
    expect(decoded.map(({ type }) => type)).toEqual([
      PayloadType.SA,
      PayloadType.KE,
      PayloadType.NONCE,
    ]);
    expect(readU16be(decoded[1]!.body)).toBe(31);
    expect(decoded[2]!.body).toEqual(new Uint8Array(32).fill(9));
  });

  it("encodes the bounded IKE proposal without an integrity transform", () => {
    const body = encodeSaBody([ikeSaProposal()]);
    expect(body[5]).toBe(1); // IKE protocol id
    expect(body[7]).toBe(3); // ENCR, PRF, DH
    expect(bytesToHex(body)).toBe(
      "00000024010100030300000c01000014800e00800300000802000005000000080400001f",
    );
  });

  it("encodes a Child-SA proposal with receiver SPI, AES-GCM, and transform 0 ESN", () => {
    const spi = hexToBytes("a1b2c3d4");
    const body = encodeSaBody([childSaProposal(spi)]);
    expect(body[5]).toBe(3); // ESP
    expect(body[6]).toBe(4);
    expect(body[7]).toBe(2);
    expect(body.slice(8, 12)).toEqual(spi);
    expect(bytesToHex(body)).toBe(
      "0000002001030402a1b2c3d40300000c01000014800e00800000000805000000",
    );
  });

  it("encodes ID, AUTH, and USE_TRANSPORT_MODE bodies", () => {
    expect(encodeIdBody(2, utf8("initiator.example")).slice(0, 4)).toEqual(
      Uint8Array.of(2, 0, 0, 0),
    );
    expect(encodeAuthBody(2, new Uint8Array(32)).slice(0, 4)).toEqual(
      Uint8Array.of(2, 0, 0, 0),
    );
    const notify = encodeNotifyBody({ messageType: USE_TRANSPORT_MODE });
    expect(readU16be(notify, 2)).toBe(USE_TRANSPORT_MODE);
  });

  it("encodes and independently decodes one IPv4 traffic selector", () => {
    const selector: TrafficSelector = {
      sourceAddress: addressRange("192.0.2.10", "192.0.2.40"),
      destinationAddress: addressRange("198.51.100.16", "198.51.100.31"),
      sourcePort: anyPort(),
      destinationPort: portRange(22),
      protocol: 6,
    };
    expect(decodeSingleTsBody(encodeTsBody(selector, "source"))).toEqual({
      protocol: 6,
      ports: { start: 0, end: 65_535 },
      addresses: {
        start: readU32be(hexToBytes("c000020a")),
        end: readU32be(hexToBytes("c0000228")),
      },
    });
    expect(decodeSingleTsBody(encodeTsBody(selector, "destination"))).toEqual({
      protocol: 6,
      ports: { start: 22, end: 22 },
      addresses: {
        start: readU32be(hexToBytes("c6336410")),
        end: readU32be(hexToBytes("c633641f")),
      },
    });
  });

  it("stops the outer parser at SK while retaining its first inner payload type", () => {
    const chain = encodePayloadChain([
      payload(PayloadType.SK, hexToBytes("0001020304050607aabbccdd")),
    ]);
    const mutable = chain.bytes.slice();
    mutable[0] = PayloadType.IDI;
    const decoded = decodePayloadChain(mutable, PayloadType.SK);
    expect(decoded).toHaveLength(1);
    expect(decoded[0]!.nextPayload).toBe(PayloadType.IDI);
  });

  it("fails closed on malformed headers and payload lengths", () => {
    const valid = encodeIkeMessage({
      initiatorSpi: SPI_I,
      responderSpi: SPI_R,
      exchangeType: ExchangeType.IKE_AUTH,
      flags: IKE_FLAG_INITIATOR,
      messageId: 1,
      payloads: [payload(PayloadType.IDI, encodeIdBody(2, utf8("i.example")))],
    });
    const wrongLength = valid.slice();
    wrongLength[27] ^= 1;
    expect(() => parseIkeHeader(wrongLength)).toThrow(/length/);
    const body = valid.slice(28);
    body[2] = 0xff;
    body[3] = 0xff;
    expect(() => decodePayloadChain(body, PayloadType.IDI)).toThrow(/length/);
    expect(() => decodePayloadChain(Uint8Array.of(0), PayloadType.IDI)).toThrow(
      /Truncated/,
    );
  });
});
