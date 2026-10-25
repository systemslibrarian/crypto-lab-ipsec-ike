import {
  bytesEqual,
  bytesToHex,
  concatBytes,
  readU32be,
  requireLength,
  u32be,
  u64be,
} from "./bytes";
import { aesGcmOpen, aesGcmSeal } from "./primitives";

export const ESP_WINDOW_SIZE = 64;
export const ESP_MAX_SEQUENCE = 0xffffffff;
const ESP_TAG_BYTES = 16;
const ESP_EXPLICIT_IV_BYTES = 8;

export type EspDirection = "initiator-to-responder" | "responder-to-initiator";

export interface ReplayWindow {
  highest: number;
  bitmap: bigint;
  size: number;
}

export type ReplayRefusal = "replay" | "too-old" | "invalid-sequence";

export interface EspSa {
  spi: number;
  key: Uint8Array;
  salt: Uint8Array;
  direction: EspDirection;
  generation: number;
  active: boolean;
  /** RFC counter state before the next send; zero means the first packet will carry one. */
  sequenceCounter: number;
  replayWindow: ReplayWindow;
  usedNonces: readonly string[];
}

export interface SealedEspPacket {
  packet: Uint8Array;
  spi: number;
  sequence: number;
  aad: Uint8Array;
  explicitIv: Uint8Array;
  nonce: Uint8Array;
  payload: Uint8Array;
  padding: Uint8Array;
  padLength: number;
  nextHeader: number;
  plaintext: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  nextSa: EspSa;
}

type AeadSealer = typeof aesGcmSeal;

interface ReservedEspPacket {
  spi: number;
  sequence: number;
  aad: Uint8Array;
  explicitIv: Uint8Array;
  nonce: Uint8Array;
  payload: Uint8Array;
  padding: Uint8Array;
  padLength: number;
  nextHeader: number;
  plaintext: Uint8Array;
  key: Uint8Array;
  nextSa: EspSa;
}

export interface EspAccepted {
  accepted: true;
  stage: "accepted";
  spi: number;
  sequence: number;
  payload: Uint8Array;
  padding: Uint8Array;
  padLength: number;
  nextHeader: number;
  windowBefore: ReplayWindow;
  windowAfter: ReplayWindow;
  sad: Map<number, EspSa>;
}

export interface EspRejected {
  accepted: false;
  stage:
    | "packet-shape"
    | "sad-lookup"
    | "replay-precheck"
    | "authentication"
    | "trailer";
  reason: string;
  spi?: number;
  sequence?: number;
  windowBefore?: ReplayWindow;
  windowAfter?: ReplayWindow;
  sad: Map<number, EspSa>;
}

export type EspReceiveResult = EspAccepted | EspRejected;

export function createReplayWindow(size = ESP_WINDOW_SIZE): ReplayWindow {
  if (!Number.isInteger(size) || size < 1 || size > 1024) {
    throw new RangeError("Replay-window size must be between 1 and 1,024.");
  }
  return { highest: 0, bitmap: 0n, size };
}

export function replayPrecheck(
  window: ReplayWindow,
  sequence: number,
): true | ReplayRefusal {
  validateWindow(window);
  if (
    !Number.isInteger(sequence) ||
    sequence < 1 ||
    sequence > ESP_MAX_SEQUENCE
  ) {
    return "invalid-sequence";
  }
  if (window.highest === 0 || sequence > window.highest) return true;
  const age = window.highest - sequence;
  if (age >= window.size) return "too-old";
  return ((window.bitmap >> BigInt(age)) & 1n) === 1n ? "replay" : true;
}

export function commitReplay(
  window: ReplayWindow,
  sequence: number,
): ReplayWindow {
  const verdict = replayPrecheck(window, sequence);
  if (verdict !== true)
    throw new Error(`Cannot commit ESP sequence: ${verdict}.`);
  if (window.highest === 0) return { ...window, highest: sequence, bitmap: 1n };
  if (sequence > window.highest) {
    const shift = sequence - window.highest;
    const shifted = shift >= window.size ? 0n : window.bitmap << BigInt(shift);
    const mask = (1n << BigInt(window.size)) - 1n;
    return { ...window, highest: sequence, bitmap: (shifted | 1n) & mask };
  }
  const age = window.highest - sequence;
  return { ...window, bitmap: window.bitmap | (1n << BigInt(age)) };
}

export function createEspSa(options: {
  spi: number;
  keyWithSalt: Uint8Array;
  direction: EspDirection;
  generation?: number;
  replayWindowSize?: number;
}): EspSa {
  validateSpi(options.spi);
  requireLength(options.keyWithSalt, 20, "ESP AES-GCM key material");
  return {
    spi: options.spi,
    key: options.keyWithSalt.slice(0, 16),
    salt: options.keyWithSalt.slice(16),
    direction: options.direction,
    generation: options.generation ?? 1,
    active: true,
    sequenceCounter: 0,
    replayWindow: createReplayWindow(options.replayWindowSize),
    usedNonces: [],
  };
}

/**
 * Stateful outbound SA owner. Sequence and IV state is reserved before AEAD
 * begins and remains burned if encryption fails, preventing accidental nonce
 * reuse by a caller that catches the failure and retries.
 */
export class EspSender {
  #sa: EspSa;
  readonly #sealer: AeadSealer;

  constructor(sa: EspSa, sealer: AeadSealer = aesGcmSeal) {
    validateSa(sa);
    this.#sa = cloneSa(sa);
    this.#sealer = sealer;
  }

  snapshot(): EspSa {
    return cloneSa(this.#sa);
  }

  async send(
    payloadBytes: Uint8Array,
    nextHeader: number,
  ): Promise<SealedEspPacket> {
    return this.#seal(payloadBytes, nextHeader, this.#sa.spi);
  }

  /**
   * Teaching-only negative control: reserve the next nonce from this same SA
   * owner, but authenticate a different receiver SPI. This isolates SAD key
   * selection from ordinary authenticated-header tampering.
   */
  async sendWithReceiverSpiControl(
    payloadBytes: Uint8Array,
    nextHeader: number,
    receiverSpi: number,
  ): Promise<SealedEspPacket> {
    validateSpi(receiverSpi);
    return this.#seal(payloadBytes, nextHeader, receiverSpi);
  }

  async #seal(
    payloadBytes: Uint8Array,
    nextHeader: number,
    packetSpi: number,
  ): Promise<SealedEspPacket> {
    const reserved = reserveEspPacket(
      this.#sa,
      payloadBytes,
      nextHeader,
      packetSpi,
    );
    this.#sa = reserved.nextSa;
    const sealed = await this.#sealer(
      reserved.key,
      reserved.nonce,
      reserved.plaintext,
      reserved.aad,
    );
    return {
      packet: concatBytes(
        reserved.aad,
        reserved.explicitIv,
        sealed.ciphertext,
        sealed.tag,
      ),
      spi: reserved.spi,
      sequence: reserved.sequence,
      aad: reserved.aad,
      explicitIv: reserved.explicitIv,
      nonce: reserved.nonce,
      payload: reserved.payload,
      padding: reserved.padding,
      padLength: reserved.padLength,
      nextHeader: reserved.nextHeader,
      plaintext: reserved.plaintext,
      ciphertext: sealed.ciphertext,
      tag: sealed.tag,
      nextSa: cloneSa(reserved.nextSa),
    };
  }
}

function reserveEspPacket(
  sa: EspSa,
  payloadBytes: Uint8Array,
  nextHeader: number,
  packetSpi: number,
): ReservedEspPacket {
  validateSa(sa);
  validateOctet(nextHeader, "ESP next-header value");
  if (!sa.active) throw new Error("Cannot send with a retired ESP SA.");
  if (sa.sequenceCounter >= ESP_MAX_SEQUENCE) {
    throw new Error(
      "ESP sequence space is exhausted; replace the SA before wrap.",
    );
  }
  const sequence = sa.sequenceCounter + 1;
  const aad = concatBytes(u32be(packetSpi), u32be(sequence));
  const explicitIv = u64be(BigInt(sequence));
  const nonce = concatBytes(sa.salt, explicitIv);
  const nonceHex = bytesToHex(nonce);
  if (sa.usedNonces.includes(nonceHex)) {
    throw new Error("Repeated AES-GCM nonce under one ESP key was refused.");
  }
  const padLength = (4 - ((payloadBytes.length + 2) % 4)) % 4;
  const padding = Uint8Array.from(
    { length: padLength },
    (_, index) => index + 1,
  );
  const plaintext = concatBytes(
    payloadBytes,
    padding,
    Uint8Array.of(padLength, nextHeader),
  );
  return {
    spi: packetSpi,
    sequence,
    aad,
    explicitIv,
    nonce,
    payload: payloadBytes.slice(),
    padding,
    padLength,
    nextHeader,
    plaintext,
    key: sa.key.slice(),
    nextSa: {
      ...sa,
      sequenceCounter: sequence,
      usedNonces: [...sa.usedNonces, nonceHex],
    },
  };
}

export async function receiveEspPacket(
  sad: ReadonlyMap<number, EspSa>,
  packet: Uint8Array,
): Promise<EspReceiveResult> {
  const unchanged = cloneSad(sad);
  if (packet.length < 8 + ESP_EXPLICIT_IV_BYTES + ESP_TAG_BYTES + 2) {
    return {
      accepted: false,
      stage: "packet-shape",
      reason:
        "ESP packet is too short for SPI, sequence, IV, trailer, and tag.",
      sad: unchanged,
    };
  }
  const spi = readU32be(packet, 0);
  const sequence = readU32be(packet, 4);
  const sa = unchanged.get(spi);
  if (!sa || !sa.active) {
    return {
      accepted: false,
      stage: "sad-lookup",
      reason: `No active inbound SA matches SPI 0x${spi.toString(16).padStart(8, "0")}.`,
      spi,
      sequence,
      sad: unchanged,
    };
  }
  validateSa(sa);
  const windowBefore = { ...sa.replayWindow };
  const replay = replayPrecheck(windowBefore, sequence);
  if (replay !== true) {
    return {
      accepted: false,
      stage: "replay-precheck",
      reason: `Sequence ${sequence} was refused as ${replay}.`,
      spi,
      sequence,
      windowBefore,
      windowAfter: { ...windowBefore },
      sad: unchanged,
    };
  }

  const aad = packet.slice(0, 8);
  const explicitIv = packet.slice(8, 16);
  const ciphertext = packet.slice(16, -ESP_TAG_BYTES);
  const tag = packet.slice(-ESP_TAG_BYTES);
  const nonce = concatBytes(sa.salt, explicitIv);
  let plaintext: Uint8Array;
  try {
    plaintext = await aesGcmOpen(sa.key, nonce, ciphertext, tag, aad);
  } catch {
    return {
      accepted: false,
      stage: "authentication",
      reason: "AES-GCM authentication failed; replay state was not advanced.",
      spi,
      sequence,
      windowBefore,
      windowAfter: { ...windowBefore },
      sad: unchanged,
    };
  }

  // RFC 4303 advances anti-replay state after integrity succeeds. An
  // authenticated but malformed trailer is not released, but its sequence is
  // consumed; only an unauthenticated packet leaves the window untouched.
  const windowAfter = commitReplay(windowBefore, sequence);
  const updatedSa = cloneSa(sa);
  updatedSa.replayWindow = windowAfter;
  const updatedSad = cloneSad(unchanged);
  updatedSad.set(spi, updatedSa);

  if (!bytesEqual(explicitIv, u64be(BigInt(sequence)))) {
    return {
      accepted: false,
      stage: "trailer",
      reason:
        "Authenticated explicit IV violates this profile's sequence-derived IV rule.",
      spi,
      sequence,
      windowBefore,
      windowAfter,
      sad: updatedSad,
    };
  }
  if (plaintext.length < 2) {
    return trailerRefusal(
      "Authenticated ESP plaintext is too short for its trailer.",
    );
  }
  const nextHeader = plaintext.at(-1)!;
  const padLength = plaintext.at(-2)!;
  if (padLength + 2 > plaintext.length) {
    return trailerRefusal(
      "Authenticated ESP pad length exceeds the plaintext.",
    );
  }
  const payloadEnd = plaintext.length - 2 - padLength;
  if (plaintext.length % 4 !== 0) {
    return trailerRefusal(
      "Authenticated ESP plaintext violates this profile's four-octet trailer alignment.",
    );
  }
  const minimalPadLength = (4 - ((payloadEnd + 2) % 4)) % 4;
  if (padLength !== minimalPadLength) {
    return trailerRefusal(
      "Authenticated ESP padding is not minimal for this teaching profile.",
    );
  }
  const padding = plaintext.slice(payloadEnd, -2);
  const expectedPadding = Uint8Array.from(
    { length: padLength },
    (_, index) => index + 1,
  );
  if (!bytesEqual(padding, expectedPadding)) {
    return trailerRefusal(
      "Authenticated ESP padding violates this profile's canonical padding.",
    );
  }

  return {
    accepted: true,
    stage: "accepted",
    spi,
    sequence,
    payload: plaintext.slice(0, payloadEnd),
    padding,
    padLength,
    nextHeader,
    windowBefore,
    windowAfter,
    sad: updatedSad,
  };

  function trailerRefusal(reason: string): EspRejected {
    return {
      accepted: false,
      stage: "trailer",
      reason,
      spi,
      sequence,
      windowBefore,
      windowAfter,
      sad: updatedSad,
    };
  }
}

export function installSa(
  sad: ReadonlyMap<number, EspSa>,
  sa: EspSa,
): Map<number, EspSa> {
  validateSa(sa);
  const updated = cloneSad(sad);
  if (updated.has(sa.spi))
    throw new Error("SAD already contains this inbound SPI.");
  updated.set(sa.spi, cloneSa(sa));
  return updated;
}

export function retireSa(
  sad: ReadonlyMap<number, EspSa>,
  spi: number,
): Map<number, EspSa> {
  validateSpi(spi);
  const existing = sad.get(spi);
  if (!existing) throw new Error("Cannot retire an SPI that is not installed.");
  const updated = cloneSad(sad);
  const retired = cloneSa(existing);
  retired.active = false;
  updated.set(spi, retired);
  return updated;
}

export function createChildSaPair(options: {
  initiatorToResponderKeymat: Uint8Array;
  responderToInitiatorKeymat: Uint8Array;
  /** SPI chosen by the responder for packets it receives from the initiator. */
  responderInboundSpi: number;
  /** SPI chosen by the initiator for packets it receives from the responder. */
  initiatorInboundSpi: number;
  generation?: number;
}): { initiatorToResponder: EspSa; responderToInitiator: EspSa } {
  const generation = options.generation ?? 1;
  return {
    initiatorToResponder: createEspSa({
      spi: options.responderInboundSpi,
      keyWithSalt: options.initiatorToResponderKeymat,
      direction: "initiator-to-responder",
      generation,
    }),
    responderToInitiator: createEspSa({
      spi: options.initiatorInboundSpi,
      keyWithSalt: options.responderToInitiatorKeymat,
      direction: "responder-to-initiator",
      generation,
    }),
  };
}

function cloneSad(sad: ReadonlyMap<number, EspSa>): Map<number, EspSa> {
  return new Map(Array.from(sad, ([spi, sa]) => [spi, cloneSa(sa)]));
}

function cloneSa(sa: EspSa): EspSa {
  return {
    ...sa,
    key: sa.key.slice(),
    salt: sa.salt.slice(),
    replayWindow: { ...sa.replayWindow },
    usedNonces: [...sa.usedNonces],
  };
}

function validateWindow(window: ReplayWindow): void {
  if (
    !Number.isInteger(window.highest) ||
    window.highest < 0 ||
    window.highest > ESP_MAX_SEQUENCE ||
    !Number.isInteger(window.size) ||
    window.size < 1 ||
    window.size > 1024 ||
    window.bitmap < 0n ||
    window.bitmap >= 1n << BigInt(window.size)
  ) {
    throw new RangeError("Invalid ESP replay-window state.");
  }
  const validBitCount = Math.min(window.highest, window.size);
  const coherent =
    window.highest === 0
      ? window.bitmap === 0n
      : (window.bitmap & 1n) === 1n &&
        window.bitmap < 1n << BigInt(validBitCount);
  if (!coherent) {
    throw new RangeError("Impossible ESP replay-window bitmap state.");
  }
}

function validateSa(sa: EspSa): void {
  validateSpi(sa.spi);
  requireLength(sa.key, 16, "ESP AES-128 key");
  requireLength(sa.salt, 4, "ESP salt");
  validateWindow(sa.replayWindow);
  if (
    !Number.isInteger(sa.sequenceCounter) ||
    sa.sequenceCounter < 0 ||
    sa.sequenceCounter > ESP_MAX_SEQUENCE
  ) {
    throw new RangeError("Invalid ESP outbound sequence counter.");
  }
}

function validateSpi(spi: number): void {
  if (!Number.isInteger(spi) || spi < 256 || spi > ESP_MAX_SEQUENCE) {
    throw new RangeError(
      "ESP SPI must be an allocated 32-bit value greater than 255.",
    );
  }
}

function validateOctet(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new RangeError(`${label} must be an octet.`);
  }
}
