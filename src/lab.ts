import {
  bytesEqual,
  bytesToHex,
  hexToBytes,
  ipv4ToBytes,
  randomBytes,
  readU32be,
  u32be,
} from "./protocol/bytes";
import {
  EspSender,
  createChildSaPair,
  createEspSa,
  installSa,
  receiveEspPacket,
  retireSa,
  type EspReceiveResult,
  type EspSa,
} from "./protocol/esp";
import { FIXED_EXPECTED, fixedHandshakeInputs } from "./protocol/fixtures";
import {
  freshHandshakeSecrets,
  runIkeHandshake,
  type HandshakeInputs,
  type HandshakeResult,
  type IpsecMode,
} from "./protocol/ike";
import {
  buildIpv4Packet,
  protectIpv4Packet,
  reconstructIpv4AfterEsp,
  sameIpv4Packet,
} from "./protocol/ipv4";
import { sha256 } from "./protocol/primitives";
import { runChildSaDelete, runChildSaRekey } from "./protocol/rekey";
import {
  addressRange,
  anyAddress,
  anyPort,
  applySpd,
  lookupRoute,
  portRange,
  type PacketFlow,
  type SpdRule,
} from "./protocol/spd";

export interface LabOptions {
  requestedMode: IpsecMode;
  responderAllowsTransport: boolean;
  initiatorAcceptsTunnelFallback: boolean;
  deterministicEvidence?: boolean;
}

export interface PolicyEvidence {
  label: string;
  flow: string;
  action: "DISCARD" | "BYPASS" | "PROTECT";
  rule: string;
  route: string;
}

export interface ReplayEvidence {
  label: string;
  accepted: boolean;
  stage: string;
  before: number | null;
  after: number | null;
  explanation: string;
}

export interface PacketEvidence {
  mode: IpsecMode;
  spi: string;
  sequence: number;
  explicitIv: string;
  aad: string;
  nonce: string;
  ciphertext: string;
  padding: string;
  padLength: number;
  nextHeader: number;
  tag: string;
  packet: string;
  original: string;
  protectedBytes: string;
  outer: string;
  outerHeader: string;
  protectedMeaning: string;
  clearMeaning: string;
  reconstructedExactly: boolean;
  checksumVerified: boolean;
}

export interface RekeyEvidence {
  requestIv: string;
  responseIv: string;
  newInitiatorInboundSpi: string;
  newResponderInboundSpi: string;
  oldAndNewAccepted: boolean;
  wrongOldKeyControlAccepted: boolean;
  oldOverlapSequence: number;
  wrongKeyControlSequence: number;
  retiredOldSequence: number;
  wrongOldKeyStage: string;
  retiredOldStage: string;
  newSequence: number;
  newI2rKey: string;
  newI2rSalt: string;
  newR2iKey: string;
  newR2iSalt: string;
  replayWindowsStartAt: number;
  deleteRequestSpi: string;
  deleteResponseSpi: string;
  deleteExchangeType: number;
}

export interface FallbackDeleteEvidence {
  requestMessageId: number;
  requestSpi: string;
  responseSpi: string;
  requestPayloadType: number;
  bothDirectionsRetired: boolean;
}

export interface LabRun {
  source: "fresh learner run" | "explicit deterministic evidence";
  runToken: string;
  options: LabOptions;
  policy: PolicyEvidence[];
  handshake: HandshakeResult;
  initRequestHash: string;
  initResponseHash: string;
  authRequestHash: string;
  authResponseHash: string;
  fixedOracleMatched: boolean | null;
  initialInitiatorInboundSpi: string;
  initialResponderInboundSpi: string;
  packet: PacketEvidence | null;
  replay: ReplayEvidence[];
  rekey: RekeyEvidence | null;
  fallbackDeletion: FallbackDeleteEvidence | null;
}

export async function runLab(options: LabOptions): Promise<LabRun> {
  const inputs = options.deterministicEvidence
    ? deterministicInputs(options)
    : freshInputs(options);
  const handshake = await runIkeHandshake(inputs);
  const hashes = await Promise.all([
    sha256(handshake.ikeSaInitRequest),
    sha256(handshake.ikeSaInitResponse),
    sha256(handshake.ikeAuthRequest.message),
    sha256(handshake.ikeAuthResponse.message),
  ]);
  const established = handshake.mode.childState === "established";
  const pair = createChildSaPair({
    initiatorToResponderKeymat: handshake.childKeys.initiatorToResponder,
    responderToInitiatorKeymat: handshake.childKeys.responderToInitiator,
    responderInboundSpi: readU32be(inputs.responderInboundChildSpi),
    initiatorInboundSpi: readU32be(inputs.initiatorInboundChildSpi),
  });
  const fallbackDeletion = established
    ? null
    : await fallbackDeleteEvidence(inputs, handshake, pair);
  let packet: PacketEvidence | null = null;
  let replay: ReplayEvidence[] = [];
  let rekey: RekeyEvidence | null = null;
  if (established) {
    // One owner allocates every nonce used under this outbound Child-SA key.
    // Receiver scenarios may branch their replay state, but they never fork the
    // sender or re-encrypt different plaintext under a prior key/nonce pair.
    const outboundSender = new EspSender(pair.initiatorToResponder);
    packet = await packetEvidence(
      handshake.mode.establishedMode,
      pair.initiatorToResponder,
      outboundSender,
    );
    replay = await replayEvidence(pair.initiatorToResponder, outboundSender);
    rekey = await rekeyEvidence(
      inputs,
      handshake,
      pair,
      outboundSender,
      Boolean(options.deterministicEvidence),
    );
  }
  const fixedOracleMatched = options.deterministicEvidence
    ? bytesToHex(hashes[0]) === FIXED_EXPECTED.initRequestSha256 &&
      bytesToHex(hashes[1]) === FIXED_EXPECTED.initResponseSha256 &&
      bytesToHex(hashes[2]) === FIXED_EXPECTED.authRequestSha256 &&
      bytesToHex(hashes[3]) === FIXED_EXPECTED.authResponseSha256
    : null;

  return {
    source: options.deterministicEvidence
      ? "explicit deterministic evidence"
      : "fresh learner run",
    runToken: bytesToHex(await sha256(handshake.ikeAuthRequest.message)).slice(
      0,
      16,
    ),
    options,
    policy: policyEvidence(),
    handshake,
    initRequestHash: bytesToHex(hashes[0]),
    initResponseHash: bytesToHex(hashes[1]),
    authRequestHash: bytesToHex(hashes[2]),
    authResponseHash: bytesToHex(hashes[3]),
    fixedOracleMatched,
    initialInitiatorInboundSpi: `0x${readU32be(inputs.initiatorInboundChildSpi).toString(16).padStart(8, "0")}`,
    initialResponderInboundSpi: `0x${readU32be(inputs.responderInboundChildSpi).toString(16).padStart(8, "0")}`,
    packet,
    replay,
    rekey,
    fallbackDeletion,
  };
}

function freshInputs(options: LabOptions): HandshakeInputs {
  const secrets = freshHandshakeSecrets();
  return {
    ...secrets,
    psk: randomBytes(32),
    initiatorIdentity: {
      type: 1,
      data: ipv4ToBytes("192.0.2.10"),
      label: "192.0.2.10",
    },
    responderIdentity: {
      type: 1,
      data: ipv4ToBytes("198.51.100.20"),
      label: "198.51.100.20",
    },
    offeredSelector: {
      sourceAddress: addressRange("192.0.2.0", "192.0.2.255"),
      destinationAddress: addressRange("198.51.100.0", "198.51.100.255"),
      sourcePort: anyPort(),
      destinationPort: anyPort(),
      protocol: 0,
    },
    responderPolicy: {
      sourceAddress: addressRange("192.0.2.10"),
      destinationAddress: addressRange("198.51.100.20"),
      sourcePort: anyPort(),
      destinationPort: anyPort(),
      protocol: 1,
    },
    requestedMode: options.requestedMode,
    responderAllowsTransport: options.responderAllowsTransport,
    initiatorAcceptsTunnelFallback: options.initiatorAcceptsTunnelFallback,
    rejectAllZeroDh: true,
  };
}

function deterministicInputs(options: LabOptions): HandshakeInputs {
  return {
    ...fixedHandshakeInputs(),
    requestedMode: options.requestedMode,
    responderAllowsTransport: options.responderAllowsTransport,
    initiatorAcceptsTunnelFallback: options.initiatorAcceptsTunnelFallback,
  };
}

function policyEvidence(): PolicyEvidence[] {
  const rules: SpdRule[] = [
    {
      id: "discard-telnet",
      description: "Discard cleartext TCP/23.",
      action: "DISCARD",
      selector: {
        sourceAddress: anyAddress(),
        destinationAddress: addressRange("198.51.100.20"),
        sourcePort: anyPort(),
        destinationPort: portRange(23),
        protocol: 6,
      },
    },
    {
      id: "bypass-dns",
      description: "Bypass IPsec for the local TEST-NET DNS fixture.",
      action: "BYPASS",
      selector: {
        sourceAddress: addressRange("192.0.2.10"),
        destinationAddress: addressRange("192.0.2.53"),
        sourcePort: anyPort(),
        destinationPort: portRange(53),
        protocol: 17,
      },
    },
    {
      id: "protect-peer",
      description: "Protect traffic to the remote TEST-NET peer.",
      action: "PROTECT",
      selector: {
        sourceAddress: addressRange("192.0.2.0", "192.0.2.255"),
        destinationAddress: addressRange("198.51.100.0", "198.51.100.255"),
        sourcePort: anyPort(),
        destinationPort: anyPort(),
        protocol: 0,
      },
    },
    {
      id: "default-discard",
      description: "Discard every unmatched flow.",
      action: "DISCARD",
      selector: {
        sourceAddress: anyAddress(),
        destinationAddress: anyAddress(),
        sourcePort: anyPort(),
        destinationPort: anyPort(),
        protocol: 0,
      },
    },
  ];
  const routes = [
    {
      id: "local-net",
      destination: addressRange("192.0.2.0", "192.0.2.255"),
      nextHop: "on-link",
      interfaceName: "lan0",
    },
    {
      id: "remote-net",
      destination: addressRange("198.51.100.0", "198.51.100.255"),
      nextHop: "203.0.113.1",
      interfaceName: "wan0",
    },
  ];
  const cases: Array<{ label: string; flow: PacketFlow }> = [
    {
      label: "cleartext Telnet",
      flow: {
        source: "192.0.2.10",
        destination: "198.51.100.20",
        protocol: 6,
        sourcePort: 49_152,
        destinationPort: 23,
      },
    },
    {
      label: "local DNS",
      flow: {
        source: "192.0.2.10",
        destination: "192.0.2.53",
        protocol: 17,
        sourcePort: 53_000,
        destinationPort: 53,
      },
    },
    {
      label: "remote ICMP",
      flow: {
        source: "192.0.2.10",
        destination: "198.51.100.20",
        protocol: 1,
        sourcePort: 0,
        destinationPort: 0,
      },
    },
  ];
  return cases.map(({ label, flow }) => {
    const decision = applySpd(rules, flow);
    const route = lookupRoute(routes, flow.destination);
    const destinationPort =
      flow.protocol === 6 || flow.protocol === 17
        ? `, destination port ${flow.destinationPort}`
        : "";
    return {
      label,
      flow: `${flow.source} → ${flow.destination}, IP protocol ${flow.protocol}${destinationPort}`,
      action: decision.action,
      rule: `${decision.ruleIndex + 1}. ${decision.matchedRule.id}`,
      route: `${route.interfaceName} via ${route.nextHop}`,
    };
  });
}

function originalPacket() {
  return buildIpv4Packet({
    source: "192.0.2.10",
    destination: "198.51.100.20",
    protocol: 1,
    identification: 0x4242,
    payload: Uint8Array.from([
      0x08, 0x00, 0xe4, 0xa9, 0x12, 0x34, 0x00, 0x01, 0x63, 0x72, 0x79, 0x70,
      0x74, 0x6f, 0x2d, 0x6c, 0x61, 0x62, 0x21,
    ]),
  });
}

async function packetEvidence(
  mode: IpsecMode,
  inboundSa: EspSa,
  sender: EspSender,
): Promise<PacketEvidence> {
  const original = originalPacket();
  const protectedPacket = await protectIpv4Packet({
    mode,
    original,
    sender,
    tunnelSource: mode === "tunnel" ? "203.0.113.1" : undefined,
    tunnelDestination: mode === "tunnel" ? "203.0.113.2" : undefined,
  });
  const opened = await receiveEspPacket(
    installSa(new Map(), inboundSa),
    protectedPacket.esp.packet,
  );
  if (!opened.accepted)
    throw new Error(`Internal ESP fixture failed at ${opened.stage}.`);
  const reconstructed = reconstructIpv4AfterEsp({
    mode,
    outer: protectedPacket.outer,
    accepted: opened,
  });
  return {
    mode,
    spi: `0x${protectedPacket.esp.spi.toString(16).padStart(8, "0")}`,
    sequence: protectedPacket.esp.sequence,
    explicitIv: bytesToHex(protectedPacket.esp.explicitIv),
    aad: bytesToHex(protectedPacket.esp.aad),
    nonce: bytesToHex(protectedPacket.esp.nonce),
    ciphertext: bytesToHex(protectedPacket.esp.ciphertext),
    padding: bytesToHex(protectedPacket.esp.padding),
    padLength: protectedPacket.esp.padLength,
    nextHeader: protectedPacket.esp.nextHeader,
    tag: bytesToHex(protectedPacket.esp.tag),
    packet: bytesToHex(protectedPacket.esp.packet),
    original: bytesToHex(original.bytes),
    protectedBytes: bytesToHex(protectedPacket.protectedBytes),
    outer: bytesToHex(protectedPacket.outer.bytes),
    outerHeader: bytesToHex(protectedPacket.outer.header),
    protectedMeaning: protectedPacket.protectedMeaning,
    clearMeaning: protectedPacket.clearMeaning,
    reconstructedExactly: sameIpv4Packet(reconstructed.packet, original),
    checksumVerified: reconstructed.checksumVerified,
  };
}

async function replayEvidence(
  inboundSa: EspSa,
  sender: EspSender,
): Promise<ReplayEvidence[]> {
  const firstSequence = sender.snapshot().sequenceCounter + 1;
  const packets = new Map<number, Uint8Array>();
  for (let offset = 0; offset < 66; offset += 1) {
    const sequence = firstSequence + offset;
    packets.set(
      sequence,
      (await sender.send(Uint8Array.of(sequence), 1)).packet,
    );
  }
  const packet = (sequence: number): Uint8Array => {
    const value = packets.get(sequence);
    if (!value) throw new Error(`Missing generated ESP sequence ${sequence}.`);
    return value;
  };
  const evidence: ReplayEvidence[] = [];

  let reorderedSad = installSa(new Map(), inboundSa);
  const reordered: EspReceiveResult[] = [];
  for (const sequence of [2, 4, 3]) {
    const result = await receiveEspPacket(reorderedSad, packet(sequence));
    reordered.push(result);
    reorderedSad = result.sad;
  }
  evidence.push({
    label: "valid reordering 2, 4, 3",
    accepted: reordered.every((result) => result.accepted),
    stage: reordered.map((result) => result.stage).join(" → "),
    before: 0,
    after: reorderedSad.get(inboundSa.spi)?.replayWindow.highest ?? null,
    explanation:
      "All three authentic packets occupy distinct slots in the 64-packet bitmap.",
  });
  evidence.push(
    summarizeReplay(
      "duplicate sequence 3",
      await receiveEspPacket(reorderedSad, packet(3)),
      "The non-mutating precheck rejects the already-marked slot before AES-GCM.",
    ),
  );

  let floorSad = installSa(new Map(), inboundSa);
  const high = await receiveEspPacket(floorSad, packet(66));
  floorSad = high.sad;
  evidence.push(
    summarizeReplay(
      "too-old sequence 2 after highest 66",
      await receiveEspPacket(floorSad, packet(2)),
      "Sequence 2 is outside the 64-slot window; unseen sequence 3 remains on its edge.",
    ),
  );
  const edge = await receiveEspPacket(floorSad, packet(3));
  floorSad = edge.sad;
  evidence.push(
    summarizeReplay(
      "unseen edge sequence 3",
      edge,
      "The authentic edge packet is accepted without lowering the highest sequence.",
    ),
  );

  const relabeledAhead = packet(67).slice();
  relabeledAhead.set(u32be(1000), 4);
  const modified = await receiveEspPacket(floorSad, relabeledAhead);
  evidence.push(
    summarizeReplay(
      "modified packet relabeled 1000",
      modified,
      "It passes the pure precheck but fails authentication; the window does not advance.",
    ),
  );
  evidence.push(
    summarizeReplay(
      "valid sequence 67 after failed 1000",
      await receiveEspPacket(modified.sad, packet(67)),
      "Because the bad tag did not commit replay state, the authentic lower packet still succeeds.",
    ),
  );

  const unknown = packet(2).slice();
  unknown.set(u32be(0xdeadbeef), 0);
  evidence.push(
    summarizeReplay(
      "unknown SPI 0xdeadbeef",
      await receiveEspPacket(installSa(new Map(), inboundSa), unknown),
      "SAD lookup stops processing before replay state or authentication is touched.",
    ),
  );
  return evidence;
}

function summarizeReplay(
  label: string,
  result: EspReceiveResult,
  explanation: string,
): ReplayEvidence {
  return {
    label,
    accepted: result.accepted,
    stage: result.stage,
    before: result.windowBefore?.highest ?? null,
    after: result.windowAfter?.highest ?? null,
    explanation,
  };
}

async function fallbackDeleteEvidence(
  inputs: HandshakeInputs,
  handshake: HandshakeResult,
  pair: ReturnType<typeof createChildSaPair>,
): Promise<FallbackDeleteEvidence> {
  const deletion = await runChildSaDelete({
    requester: "original-initiator",
    messageId: 2,
    keys: handshake.keys,
    originalInitiatorIkeSender: handshake.initiatorIkeSender,
    originalResponderIkeSender: handshake.responderIkeSender,
    originalInitiatorInboundSpi: pair.responderToInitiator.spi,
    originalResponderInboundSpi: pair.initiatorToResponder.spi,
  });
  const initiatorSad = retireSa(
    installSa(new Map(), pair.responderToInitiator),
    pair.responderToInitiator.spi,
  );
  const responderSad = retireSa(
    installSa(new Map(), pair.initiatorToResponder),
    pair.initiatorToResponder.spi,
  );
  return {
    requestMessageId: deletion.openedRequest.header.messageId,
    requestSpi: `0x${deletion.requestedInboundSpi.toString(16).padStart(8, "0")}`,
    responseSpi: `0x${deletion.returnedPairedInboundSpi.toString(16).padStart(8, "0")}`,
    requestPayloadType: deletion.openedRequest.payloads[0]!.type,
    bothDirectionsRetired:
      initiatorSad.get(pair.responderToInitiator.spi)?.active === false &&
      responderSad.get(pair.initiatorToResponder.spi)?.active === false,
  };
}

async function rekeyEvidence(
  inputs: HandshakeInputs,
  handshake: HandshakeResult,
  oldPair: ReturnType<typeof createChildSaPair>,
  oldSender: EspSender,
  deterministic: boolean,
): Promise<RekeyEvidence> {
  const newInitiatorInboundSpi = deterministic
    ? hexToBytes("c1c2c3c4")
    : freshAllocatedSpi([
        oldPair.initiatorToResponder.spi,
        oldPair.responderToInitiator.spi,
      ]);
  const newResponderInboundSpi = deterministic
    ? hexToBytes("d1d2d3d4")
    : freshAllocatedSpi([
        oldPair.initiatorToResponder.spi,
        oldPair.responderToInitiator.spi,
        readU32be(newInitiatorInboundSpi),
      ]);
  const result = await runChildSaRekey({
    initiatorSpi: inputs.initiatorSpi,
    responderSpi: inputs.responderSpi,
    keys: handshake.keys,
    messageId: 2,
    exchangeInitiator: "original-initiator",
    freshNonceFromExchangeInitiator: deterministic
      ? hexToBytes(
          "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        )
      : randomBytes(32),
    freshNonceFromExchangeResponder: deterministic
      ? hexToBytes(
          "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        )
      : randomBytes(32),
    newOriginalInitiatorInboundSpi: newInitiatorInboundSpi,
    newOriginalResponderInboundSpi: newResponderInboundSpi,
    oldOriginalInitiatorInboundSpi: oldPair.responderToInitiator.spi,
    oldOriginalResponderInboundSpi: oldPair.initiatorToResponder.spi,
    activeSelector: handshake.narrowedSelector,
    originalInitiatorIkeSender: handshake.initiatorIkeSender,
    originalResponderIkeSender: handshake.responderIkeSender,
    activeMode: handshake.mode.establishedMode,
    responderEchoesTransport: handshake.mode.establishedMode === "transport",
  });
  const newPair = createChildSaPair({
    initiatorToResponderKeymat: result.originalInitiatorToResponder,
    responderToInitiatorKeymat: result.originalResponderToInitiator,
    responderInboundSpi: result.originalResponderInboundSpi,
    initiatorInboundSpi: result.originalInitiatorInboundSpi,
    generation: 2,
  });

  const newSender = new EspSender(newPair.initiatorToResponder);
  const oldPacket = await oldSender.send(Uint8Array.of(0x6f, 0x6c, 0x64), 1);
  const newPacket = await newSender.send(Uint8Array.of(0x6e, 0x65, 0x77), 1);
  let overlapSad = installSa(new Map(), oldPair.initiatorToResponder);
  overlapSad = installSa(overlapSad, newPair.initiatorToResponder);
  const oldAccepted = await receiveEspPacket(overlapSad, oldPacket.packet);
  const newAccepted = await receiveEspPacket(oldAccepted.sad, newPacket.packet);

  const wrongOldKeyPacket = await oldSender.sendWithReceiverSpiControl(
    Uint8Array.of(0x77, 0x72, 0x6f, 0x6e, 0x67),
    1,
    newPair.initiatorToResponder.spi,
  );
  const wrongResult = await receiveEspPacket(
    newAccepted.sad,
    wrongOldKeyPacket.packet,
  );
  const explanatoryOldKeySa = createEspSa({
    spi: newPair.initiatorToResponder.spi,
    keyWithSalt: handshake.childKeys.initiatorToResponder,
    direction: "initiator-to-responder",
    generation: 2,
  });
  const oldKeyControl = await receiveEspPacket(
    installSa(new Map(), explanatoryOldKeySa),
    wrongOldKeyPacket.packet,
  );

  const nextOldPacket = await oldSender.send(
    Uint8Array.of(0x72, 0x65, 0x74, 0x69, 0x72, 0x65),
    1,
  );
  const deletion = await runChildSaDelete({
    requester: "original-initiator",
    messageId: 3,
    keys: handshake.keys,
    originalInitiatorIkeSender: handshake.initiatorIkeSender,
    originalResponderIkeSender: handshake.responderIkeSender,
    originalInitiatorInboundSpi: oldPair.responderToInitiator.spi,
    originalResponderInboundSpi: oldPair.initiatorToResponder.spi,
  });
  const retired = retireSa(wrongResult.sad, oldPair.initiatorToResponder.spi);
  const retiredResult = await receiveEspPacket(retired, nextOldPacket.packet);
  return {
    requestIv: bytesToHex(result.request.explicitIv),
    responseIv: bytesToHex(result.response.explicitIv),
    newInitiatorInboundSpi: `0x${result.originalInitiatorInboundSpi.toString(16).padStart(8, "0")}`,
    newResponderInboundSpi: `0x${result.originalResponderInboundSpi.toString(16).padStart(8, "0")}`,
    oldAndNewAccepted: oldAccepted.accepted && newAccepted.accepted,
    wrongOldKeyControlAccepted: oldKeyControl.accepted,
    oldOverlapSequence: oldPacket.sequence,
    wrongKeyControlSequence: wrongOldKeyPacket.sequence,
    retiredOldSequence: nextOldPacket.sequence,
    wrongOldKeyStage: wrongResult.stage,
    retiredOldStage: retiredResult.stage,
    newSequence: newPacket.sequence,
    newI2rKey: bytesToHex(newPair.initiatorToResponder.key),
    newI2rSalt: bytesToHex(newPair.initiatorToResponder.salt),
    newR2iKey: bytesToHex(newPair.responderToInitiator.key),
    newR2iSalt: bytesToHex(newPair.responderToInitiator.salt),
    replayWindowsStartAt: Math.max(
      newPair.initiatorToResponder.replayWindow.highest,
      newPair.responderToInitiator.replayWindow.highest,
    ),
    deleteRequestSpi: `0x${deletion.requestedInboundSpi.toString(16).padStart(8, "0")}`,
    deleteResponseSpi: `0x${deletion.returnedPairedInboundSpi.toString(16).padStart(8, "0")}`,
    deleteExchangeType: deletion.openedRequest.header.exchangeType,
  };
}

function freshAllocatedSpi(excluded: readonly number[]): Uint8Array {
  let bytes: Uint8Array;
  let value: number;
  do {
    bytes = randomBytes(4);
    value = readU32be(bytes);
  } while (value < 256 || excluded.includes(value));
  return bytes;
}

export function formatSelector(handshake: HandshakeResult): string {
  const selector = handshake.narrowedSelector;
  return [
    `${numberToIpv4(selector.sourceAddress.start)}–${numberToIpv4(selector.sourceAddress.end)}`,
    `ports ${selector.sourcePort.start}–${selector.sourcePort.end}`,
    `${numberToIpv4(selector.destinationAddress.start)}–${numberToIpv4(selector.destinationAddress.end)}`,
    `ports ${selector.destinationPort.start}–${selector.destinationPort.end}`,
    `protocol ${selector.protocol}`,
  ].join(" → ");
}

function numberToIpv4(value: number): string {
  return [
    value >>> 24,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}

export function childKeymatSlicesAreDistinct(run: LabRun): boolean {
  return !bytesEqual(
    run.handshake.childKeys.initiatorToResponder,
    run.handshake.childKeys.responderToInitiator,
  );
}
