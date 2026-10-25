import { describe, expect, it } from "vitest";
import {
  addressRange,
  anyAddress,
  anyPort,
  applySpd,
  describeAddressRange,
  intersectTrafficSelectors,
  lookupRoute,
  portRange,
  selectorContains,
  selectorFromFlow,
  type PacketFlow,
  type SpdRule,
  type TrafficSelector,
} from "./spd";

const sshFlow: PacketFlow = {
  source: "192.0.2.10",
  destination: "198.51.100.20",
  protocol: 6,
  sourcePort: 49_152,
  destinationPort: 22,
};

const protectSsh: SpdRule = {
  id: "protect-admin",
  description: "Protect TCP/22 to the service subnet.",
  action: "PROTECT",
  selector: {
    sourceAddress: addressRange("192.0.2.0", "192.0.2.255"),
    destinationAddress: addressRange("198.51.100.0", "198.51.100.255"),
    sourcePort: anyPort(),
    destinationPort: portRange(22),
    protocol: 6,
  },
};

const defaultDiscard: SpdRule = {
  id: "default-discard",
  description: "Discard anything not allowed above.",
  action: "DISCARD",
  selector: {
    sourceAddress: anyAddress(),
    destinationAddress: anyAddress(),
    sourcePort: anyPort(),
    destinationPort: anyPort(),
    protocol: 0,
  },
};

const bypassDns: SpdRule = {
  id: "bypass-local-dns",
  description: "Allow a bounded DNS flow outside IPsec.",
  action: "BYPASS",
  selector: {
    sourceAddress: addressRange("192.0.2.10"),
    destinationAddress: addressRange("192.0.2.53"),
    sourcePort: anyPort(),
    destinationPort: portRange(53),
    protocol: 17,
  },
};

describe("ordered Security Policy Database", () => {
  it("returns the first matching disposition and its rule index", () => {
    const result = applySpd([protectSsh, defaultDiscard], sshFlow);
    expect(result.action).toBe("PROTECT");
    expect(result.matchedRule.id).toBe("protect-admin");
    expect(result.ruleIndex).toBe(0);
  });

  it("makes order observable instead of choosing the most specific rule", () => {
    const result = applySpd([defaultDiscard, protectSsh], sshFlow);
    expect(result.action).toBe("DISCARD");
    expect(result.matchedRule.id).toBe("default-discard");
  });

  it("executes BYPASS as a distinct first-match disposition", () => {
    const dnsFlow: PacketFlow = {
      source: "192.0.2.10",
      destination: "192.0.2.53",
      protocol: 17,
      sourcePort: 53_000,
      destinationPort: 53,
    };
    expect(applySpd([bypassDns, defaultDiscard], dnsFlow)).toMatchObject({
      action: "BYPASS",
      ruleIndex: 0,
      matchedRule: { id: "bypass-local-dns" },
    });
  });

  it("requires an explicit matching policy", () => {
    expect(() =>
      applySpd([protectSsh], { ...sshFlow, destinationPort: 443 }),
    ).toThrow(/No SPD rule/);
    expect(() => applySpd([], sshFlow)).toThrow(/at least one/);
  });

  it("keeps route selection separate from the SPD action", () => {
    const routes = [
      {
        id: "default",
        destination: anyAddress(),
        nextHop: "192.0.2.1",
        interfaceName: "wan0",
      },
      {
        id: "service",
        destination: addressRange("198.51.100.0", "198.51.100.255"),
        nextHop: "192.0.2.254",
        interfaceName: "vpn0",
      },
    ];
    expect(lookupRoute(routes, sshFlow.destination).id).toBe("service");
    expect(applySpd([defaultDiscard], sshFlow).action).toBe("DISCARD");
  });
});

describe("Child-SA traffic-selector narrowing", () => {
  const offered: TrafficSelector = {
    sourceAddress: addressRange("192.0.2.0", "192.0.2.255"),
    destinationAddress: addressRange("198.51.100.0", "198.51.100.255"),
    sourcePort: anyPort(),
    destinationPort: portRange(1, 1024),
    protocol: 0,
  };
  const policy: TrafficSelector = {
    sourceAddress: addressRange("192.0.2.10", "192.0.2.40"),
    destinationAddress: addressRange("198.51.100.16", "198.51.100.31"),
    sourcePort: anyPort(),
    destinationPort: portRange(22),
    protocol: 6,
  };

  it("installs only the selector intersection", () => {
    const narrowed = intersectTrafficSelectors(offered, policy);
    expect(narrowed).not.toBeNull();
    expect(narrowed!.protocol).toBe(6);
    expect(describeAddressRange(narrowed!.sourceAddress)).toBe(
      "192.0.2.10–192.0.2.40",
    );
    expect(describeAddressRange(narrowed!.destinationAddress)).toBe(
      "198.51.100.16–198.51.100.31",
    );
    expect(narrowed!.destinationPort).toEqual({ start: 22, end: 22 });
    expect(selectorContains(offered, narrowed!)).toBe(true);
    expect(selectorContains(policy, narrowed!)).toBe(true);
  });

  it("rejects disjoint protocol or address offers", () => {
    expect(
      intersectTrafficSelectors({ ...offered, protocol: 17 }, policy),
    ).toBeNull();
    expect(
      intersectTrafficSelectors(
        { ...offered, destinationAddress: addressRange("203.0.113.1") },
        policy,
      ),
    ).toBeNull();
  });

  it("converts a concrete flow into a singleton selector", () => {
    expect(selectorContains(offered, selectorFromFlow(sshFlow))).toBe(true);
    expect(selectorFromFlow(sshFlow).destinationPort).toEqual({
      start: 22,
      end: 22,
    });
  });

  it("rejects malformed ranges and protocol numbers", () => {
    expect(() => portRange(80, 79)).toThrow(/range/);
    expect(() =>
      intersectTrafficSelectors({ ...offered, protocol: 256 }, policy),
    ).toThrow(/protocol/);
  });
});
