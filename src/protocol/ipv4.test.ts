import { describe, expect, it } from "vitest";
import { concatBytes, hexToBytes, utf8 } from "./bytes";
import { EspSender, createEspSa, receiveEspPacket } from "./esp";
import {
  IP_PROTOCOL_ESP,
  IP_PROTOCOL_IPV4,
  buildIpv4Packet,
  internetChecksum,
  parseIpv4Packet,
  protectIpv4Packet,
  reconstructIpv4AfterEsp,
  sameIpv4Packet,
} from "./ipv4";

const keymat = hexToBytes("000102030405060708090a0b0c0d0e0fa0a1a2a3");
const makeSa = () =>
  createEspSa({
    spi: 0x10203040,
    keyWithSalt: keymat,
    direction: "initiator-to-responder",
  });

describe("IPv4 transport and tunnel boundaries", () => {
  const original = buildIpv4Packet({
    source: "192.0.2.10",
    destination: "198.51.100.20",
    protocol: 17,
    payload: concatBytes(hexToBytes("c00000350015"), utf8("query")),
    identification: 0x1234,
  });

  it("builds an independently parseable IPv4 packet and checksum", () => {
    expect(original.header).toHaveLength(20);
    expect(internetChecksum(original.header)).toBe(0);
    expect(parseIpv4Packet(original.bytes)).toMatchObject({
      source: "192.0.2.10",
      destination: "198.51.100.20",
      protocol: 17,
      identification: 0x1234,
    });
  });

  it("protects only the transport segment in transport mode", async () => {
    const protectedPacket = await protectIpv4Packet({
      mode: "transport",
      original,
      sender: new EspSender(makeSa()),
    });
    expect(protectedPacket.esp.nextHeader).toBe(17);
    expect(protectedPacket.esp.payload).toEqual(original.payload);
    expect(protectedPacket.outer.source).toBe(original.source);
    expect(protectedPacket.outer.destination).toBe(original.destination);
    expect(protectedPacket.outer.protocol).toBe(IP_PROTOCOL_ESP);
    expect(protectedPacket.outer.payload).toEqual(protectedPacket.esp.packet);
    const opened = await receiveEspPacket(
      new Map([[makeSa().spi, makeSa()]]),
      protectedPacket.esp.packet,
    );
    expect(opened.accepted).toBe(true);
    if (!opened.accepted) throw new Error("fixture should open");
    const reconstructed = reconstructIpv4AfterEsp({
      mode: "transport",
      outer: protectedPacket.outer,
      accepted: opened,
    });
    expect(reconstructed.checksumVerified).toBe(true);
    expect(internetChecksum(reconstructed.packet.header)).toBe(0);
    expect(sameIpv4Packet(reconstructed.packet, original)).toBe(true);
  });

  it("protects the complete inner packet behind a new outer header in tunnel mode", async () => {
    const protectedPacket = await protectIpv4Packet({
      mode: "tunnel",
      original,
      sender: new EspSender(makeSa()),
      tunnelSource: "203.0.113.1",
      tunnelDestination: "203.0.113.2",
    });
    expect(protectedPacket.esp.nextHeader).toBe(IP_PROTOCOL_IPV4);
    expect(protectedPacket.esp.payload).toEqual(original.bytes);
    expect(protectedPacket.outer.source).toBe("203.0.113.1");
    expect(protectedPacket.outer.destination).toBe("203.0.113.2");
    const opened = await receiveEspPacket(
      new Map([[makeSa().spi, makeSa()]]),
      protectedPacket.esp.packet,
    );
    expect(opened.accepted).toBe(true);
    if (!opened.accepted) throw new Error("fixture should open");
    expect(opened.payload).toEqual(original.bytes);
    const reconstructed = reconstructIpv4AfterEsp({
      mode: "tunnel",
      outer: protectedPacket.outer,
      accepted: opened,
    });
    expect(reconstructed.packet.source).toBe(original.source);
    expect(reconstructed.checksumVerified).toBe(true);
    expect(sameIpv4Packet(reconstructed.packet, original)).toBe(true);
  });

  it("refuses invalid IPv4 checksum and missing tunnel endpoints", async () => {
    const corrupted = original.bytes.slice();
    corrupted[10] ^= 1;
    expect(() => parseIpv4Packet(corrupted)).toThrow(/checksum/);
    await expect(
      protectIpv4Packet({
        mode: "tunnel",
        original,
        sender: new EspSender(makeSa()),
      }),
    ).rejects.toThrow(/tunnel source/);
  });
});
