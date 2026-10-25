import { ipv4ToNumber } from "./bytes";

export type IpsecDisposition = "DISCARD" | "BYPASS" | "PROTECT";

export interface PacketFlow {
  source: string;
  destination: string;
  protocol: number;
  sourcePort: number;
  destinationPort: number;
}

export interface NumericRange {
  start: number;
  end: number;
}

export interface TrafficSelector {
  sourceAddress: NumericRange;
  destinationAddress: NumericRange;
  sourcePort: NumericRange;
  destinationPort: NumericRange;
  /** IANA IP protocol number; zero means any protocol in this bounded model. */
  protocol: number;
}

export interface SpdRule {
  id: string;
  description: string;
  action: IpsecDisposition;
  selector: TrafficSelector;
}

export interface SpdDecision {
  action: IpsecDisposition;
  matchedRule: SpdRule;
  ruleIndex: number;
}

export interface Route {
  id: string;
  destination: NumericRange;
  nextHop: string;
  interfaceName: string;
}

export function addressRange(start: string, end = start): NumericRange {
  const range = { start: ipv4ToNumber(start), end: ipv4ToNumber(end) };
  validateRange(range, "address");
  return range;
}

export function portRange(start: number, end = start): NumericRange {
  const range = { start, end };
  validateRange(range, "port", 0xffff);
  return range;
}

export function anyAddress(): NumericRange {
  return { start: 0, end: 0xffffffff };
}

export function anyPort(): NumericRange {
  return { start: 0, end: 0xffff };
}

export function selectorFromFlow(flow: PacketFlow): TrafficSelector {
  validateFlow(flow);
  return {
    sourceAddress: addressRange(flow.source),
    destinationAddress: addressRange(flow.destination),
    sourcePort: portRange(flow.sourcePort),
    destinationPort: portRange(flow.destinationPort),
    protocol: flow.protocol,
  };
}

export function applySpd(
  rules: readonly SpdRule[],
  flow: PacketFlow,
): SpdDecision {
  validateFlow(flow);
  if (rules.length === 0)
    throw new Error("The ordered SPD must contain at least one rule.");
  for (const [ruleIndex, rule] of rules.entries()) {
    validateRule(rule);
    if (selectorContains(rule.selector, selectorFromFlow(flow))) {
      return { action: rule.action, matchedRule: rule, ruleIndex };
    }
  }
  throw new Error(
    "No SPD rule matched; declare an explicit final policy instead of guessing.",
  );
}

export function lookupRoute(
  routes: readonly Route[],
  destination: string,
): Route {
  const numeric = ipv4ToNumber(destination);
  const candidates = routes.filter((route) => {
    validateRange(route.destination, "route address");
    return (
      numeric >= route.destination.start && numeric <= route.destination.end
    );
  });
  if (candidates.length === 0)
    throw new Error(`No route covers ${destination}.`);
  candidates.sort(
    (left, right) =>
      left.destination.end -
      left.destination.start -
      (right.destination.end - right.destination.start),
  );
  return candidates[0]!;
}

export function intersectTrafficSelectors(
  offered: TrafficSelector,
  policy: TrafficSelector,
): TrafficSelector | null {
  validateTrafficSelector(offered);
  validateTrafficSelector(policy);
  const protocol = intersectProtocol(offered.protocol, policy.protocol);
  if (protocol === null) return null;
  const sourceAddress = intersectRange(
    offered.sourceAddress,
    policy.sourceAddress,
  );
  const destinationAddress = intersectRange(
    offered.destinationAddress,
    policy.destinationAddress,
  );
  const sourcePort = intersectRange(offered.sourcePort, policy.sourcePort);
  const destinationPort = intersectRange(
    offered.destinationPort,
    policy.destinationPort,
  );
  if (!sourceAddress || !destinationAddress || !sourcePort || !destinationPort)
    return null;
  return {
    sourceAddress,
    destinationAddress,
    sourcePort,
    destinationPort,
    protocol,
  };
}

export function selectorContains(
  container: TrafficSelector,
  candidate: TrafficSelector,
): boolean {
  validateTrafficSelector(container);
  validateTrafficSelector(candidate);
  return (
    containsRange(container.sourceAddress, candidate.sourceAddress) &&
    containsRange(container.destinationAddress, candidate.destinationAddress) &&
    containsRange(container.sourcePort, candidate.sourcePort) &&
    containsRange(container.destinationPort, candidate.destinationPort) &&
    (container.protocol === 0 || container.protocol === candidate.protocol)
  );
}

export function describeAddressRange(range: NumericRange): string {
  validateRange(range, "address");
  return range.start === range.end
    ? numberToIpv4(range.start)
    : `${numberToIpv4(range.start)}–${numberToIpv4(range.end)}`;
}

function numberToIpv4(value: number): string {
  return [
    value >>> 24,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}

function intersectRange(
  left: NumericRange,
  right: NumericRange,
): NumericRange | null {
  const start = Math.max(left.start, right.start);
  const end = Math.min(left.end, right.end);
  return start <= end ? { start, end } : null;
}

function intersectProtocol(left: number, right: number): number | null {
  if (left === 0) return right;
  if (right === 0) return left;
  return left === right ? left : null;
}

function containsRange(
  container: NumericRange,
  candidate: NumericRange,
): boolean {
  return candidate.start >= container.start && candidate.end <= container.end;
}

function validateFlow(flow: PacketFlow): void {
  ipv4ToNumber(flow.source);
  ipv4ToNumber(flow.destination);
  validateProtocol(flow.protocol);
  validateRange(
    { start: flow.sourcePort, end: flow.sourcePort },
    "source port",
    0xffff,
  );
  validateRange(
    { start: flow.destinationPort, end: flow.destinationPort },
    "destination port",
    0xffff,
  );
}

function validateRule(rule: SpdRule): void {
  if (!rule.id || !rule.description)
    throw new Error("Every SPD rule needs an id and description.");
  if (!(["DISCARD", "BYPASS", "PROTECT"] as const).includes(rule.action)) {
    throw new Error(`Unknown SPD action: ${String(rule.action)}`);
  }
  validateTrafficSelector(rule.selector);
}

export function validateTrafficSelector(selector: TrafficSelector): void {
  validateRange(selector.sourceAddress, "source address");
  validateRange(selector.destinationAddress, "destination address");
  validateRange(selector.sourcePort, "source port", 0xffff);
  validateRange(selector.destinationPort, "destination port", 0xffff);
  validateProtocol(selector.protocol);
}

function validateProtocol(protocol: number): void {
  if (!Number.isInteger(protocol) || protocol < 0 || protocol > 0xff) {
    throw new RangeError("IP protocol number must be an octet.");
  }
}

function validateRange(
  range: NumericRange,
  label: string,
  maximum = 0xffffffff,
): void {
  if (
    !Number.isInteger(range.start) ||
    !Number.isInteger(range.end) ||
    range.start < 0 ||
    range.end > maximum ||
    range.start > range.end
  ) {
    throw new RangeError(`Invalid ${label} range.`);
  }
}
