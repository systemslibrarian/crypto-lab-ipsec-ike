import {
  bytesEqual,
  concatBytes,
  readU32be,
  requireLength,
  u32be,
} from "./bytes";
import {
  type IkeKeys,
  type IkeMessageSender,
  openIkeEncryptedMessage,
  prfPlus,
  type IpsecMode,
  type OpenedIkeMessage,
  type SealedIkeMessage,
} from "./ike";
import {
  ExchangeType,
  IKE_FLAG_INITIATOR,
  IKE_FLAG_RESPONSE,
  PayloadType,
  USE_TRANSPORT_MODE,
  childSaProposal,
  encodeDeleteBody,
  encodeNotifyBody,
  encodeSaBody,
  encodeTsBody,
  payload,
} from "./ike-wire";
import type { TrafficSelector } from "./spd";

export const REKEY_SA = 16_393;

export type OriginalIkeRole = "original-initiator" | "original-responder";

export interface ChildRekeyInputs {
  initiatorSpi: Uint8Array;
  responderSpi: Uint8Array;
  keys: Pick<IkeKeys, "skD" | "skEi" | "skEr">;
  messageId: number;
  exchangeInitiator: OriginalIkeRole;
  freshNonceFromExchangeInitiator: Uint8Array;
  freshNonceFromExchangeResponder: Uint8Array;
  /** New SPI chosen by the original initiator for packets it receives. */
  newOriginalInitiatorInboundSpi: Uint8Array;
  /** New SPI chosen by the original responder for packets it receives. */
  newOriginalResponderInboundSpi: Uint8Array;
  /** Old SPI expected inbound by the original initiator. */
  oldOriginalInitiatorInboundSpi: number;
  /** Old SPI expected inbound by the original responder. */
  oldOriginalResponderInboundSpi: number;
  activeSelector: TrafficSelector;
  originalInitiatorIkeSender: IkeMessageSender;
  originalResponderIkeSender: IkeMessageSender;
  activeMode: IpsecMode;
  responderEchoesTransport: boolean;
}

export interface ChildRekeyResult {
  request: SealedIkeMessage;
  response: SealedIkeMessage;
  openedRequest: OpenedIkeMessage;
  openedResponse: OpenedIkeMessage;
  exchangeInitiatorToResponder: Uint8Array;
  exchangeResponderToInitiator: Uint8Array;
  originalInitiatorToResponder: Uint8Array;
  originalResponderToInitiator: Uint8Array;
  originalInitiatorInboundSpi: number;
  originalResponderInboundSpi: number;
  modeAfter: IpsecMode;
  childState: "established" | "delete-required";
}

export interface ChildSaDeleteResult {
  request: SealedIkeMessage;
  response: SealedIkeMessage;
  openedRequest: OpenedIkeMessage;
  openedResponse: OpenedIkeMessage;
  requestedInboundSpi: number;
  returnedPairedInboundSpi: number;
}

export async function deriveChildRekeyKeys(
  skD: Uint8Array,
  freshNonceFromExchangeInitiator: Uint8Array,
  freshNonceFromExchangeResponder: Uint8Array,
): Promise<{
  exchangeInitiatorToResponder: Uint8Array;
  exchangeResponderToInitiator: Uint8Array;
}> {
  requireLength(skD, 32, "SK_d");
  validateNonce(freshNonceFromExchangeInitiator, "rekey initiator nonce");
  validateNonce(freshNonceFromExchangeResponder, "rekey responder nonce");
  const keymat = await prfPlus(
    skD,
    concatBytes(
      freshNonceFromExchangeInitiator,
      freshNonceFromExchangeResponder,
    ),
    40,
  );
  return {
    exchangeInitiatorToResponder: keymat.slice(0, 20),
    exchangeResponderToInitiator: keymat.slice(20),
  };
}

export async function runChildSaRekey(
  inputs: ChildRekeyInputs,
): Promise<ChildRekeyResult> {
  validateInputs(inputs);
  const exchangeInitiatorIsOriginal =
    inputs.exchangeInitiator === "original-initiator";
  const exchangeSelector = exchangeInitiatorIsOriginal
    ? inputs.activeSelector
    : reverseSelector(inputs.activeSelector);
  const exchangeInitiatorInboundSpi = exchangeInitiatorIsOriginal
    ? inputs.newOriginalInitiatorInboundSpi
    : inputs.newOriginalResponderInboundSpi;
  const exchangeResponderInboundSpi = exchangeInitiatorIsOriginal
    ? inputs.newOriginalResponderInboundSpi
    : inputs.newOriginalInitiatorInboundSpi;
  const rekeyedOldInboundSpi = exchangeInitiatorIsOriginal
    ? inputs.oldOriginalInitiatorInboundSpi
    : inputs.oldOriginalResponderInboundSpi;
  const requestKey = exchangeInitiatorIsOriginal
    ? inputs.keys.skEi
    : inputs.keys.skEr;
  const responseKey = exchangeInitiatorIsOriginal
    ? inputs.keys.skEr
    : inputs.keys.skEi;
  const requestSender = exchangeInitiatorIsOriginal
    ? inputs.originalInitiatorIkeSender
    : inputs.originalResponderIkeSender;
  const responseSender = exchangeInitiatorIsOriginal
    ? inputs.originalResponderIkeSender
    : inputs.originalInitiatorIkeSender;
  const requestFlags = exchangeInitiatorIsOriginal ? IKE_FLAG_INITIATOR : 0;
  const responseFlags = exchangeInitiatorIsOriginal
    ? IKE_FLAG_RESPONSE
    : IKE_FLAG_INITIATOR | IKE_FLAG_RESPONSE;

  const requestPayloads = [
    payload(
      PayloadType.NOTIFY,
      encodeNotifyBody({
        protocolId: 3,
        spi: u32be(rekeyedOldInboundSpi),
        messageType: REKEY_SA,
      }),
    ),
    payload(
      PayloadType.SA,
      encodeSaBody([childSaProposal(exchangeInitiatorInboundSpi)]),
    ),
    payload(PayloadType.NONCE, inputs.freshNonceFromExchangeInitiator),
    payload(PayloadType.TSI, encodeTsBody(exchangeSelector, "source")),
    payload(PayloadType.TSR, encodeTsBody(exchangeSelector, "destination")),
  ];
  if (inputs.activeMode === "transport") {
    requestPayloads.push(
      payload(
        PayloadType.NOTIFY,
        encodeNotifyBody({ messageType: USE_TRANSPORT_MODE }),
      ),
    );
  }
  const responsePayloads = [
    payload(
      PayloadType.SA,
      encodeSaBody([childSaProposal(exchangeResponderInboundSpi)]),
    ),
    payload(PayloadType.NONCE, inputs.freshNonceFromExchangeResponder),
    payload(PayloadType.TSI, encodeTsBody(exchangeSelector, "source")),
    payload(PayloadType.TSR, encodeTsBody(exchangeSelector, "destination")),
  ];
  if (inputs.activeMode === "transport" && inputs.responderEchoesTransport) {
    responsePayloads.push(
      payload(
        PayloadType.NOTIFY,
        encodeNotifyBody({ messageType: USE_TRANSPORT_MODE }),
      ),
    );
  }

  const request = await requestSender.send({
    exchangeType: ExchangeType.CREATE_CHILD_SA,
    flags: requestFlags,
    messageId: inputs.messageId,
    innerPayloads: requestPayloads,
  });
  const response = await responseSender.send({
    exchangeType: ExchangeType.CREATE_CHILD_SA,
    flags: responseFlags,
    messageId: inputs.messageId,
    innerPayloads: responsePayloads,
  });
  const openedRequest = await openIkeEncryptedMessage(
    request.message,
    requestKey,
  );
  const openedResponse = await openIkeEncryptedMessage(
    response.message,
    responseKey,
  );
  const exchangeKeys = await deriveChildRekeyKeys(
    inputs.keys.skD,
    inputs.freshNonceFromExchangeInitiator,
    inputs.freshNonceFromExchangeResponder,
  );
  const originalInitiatorToResponder = exchangeInitiatorIsOriginal
    ? exchangeKeys.exchangeInitiatorToResponder
    : exchangeKeys.exchangeResponderToInitiator;
  const originalResponderToInitiator = exchangeInitiatorIsOriginal
    ? exchangeKeys.exchangeResponderToInitiator
    : exchangeKeys.exchangeInitiatorToResponder;
  const transportFailed =
    inputs.activeMode === "transport" && !inputs.responderEchoesTransport;
  return {
    request,
    response,
    openedRequest,
    openedResponse,
    ...exchangeKeys,
    originalInitiatorToResponder,
    originalResponderToInitiator,
    originalInitiatorInboundSpi: readU32be(
      inputs.newOriginalInitiatorInboundSpi,
    ),
    originalResponderInboundSpi: readU32be(
      inputs.newOriginalResponderInboundSpi,
    ),
    modeAfter: transportFailed ? "tunnel" : inputs.activeMode,
    childState: transportFailed ? "delete-required" : "established",
  };
}

export async function sealChildSaDelete(options: {
  senderRole: OriginalIkeRole;
  messageId: number;
  ikeSender: IkeMessageSender;
  /** SPI the Delete sender expected inbound on the old pair. */
  expectedInboundSpi: number;
}): Promise<SealedIkeMessage> {
  validateAllocatedSpi(options.expectedInboundSpi, "deleted Child-SA SPI");
  if (
    options.senderRole !== "original-initiator" &&
    options.senderRole !== "original-responder"
  ) {
    throw new TypeError("Delete sender role is invalid.");
  }
  return options.ikeSender.send({
    exchangeType: ExchangeType.INFORMATIONAL,
    flags: options.senderRole === "original-initiator" ? IKE_FLAG_INITIATOR : 0,
    messageId: options.messageId,
    innerPayloads: [
      payload(
        PayloadType.DELETE,
        encodeDeleteBody(3, [u32be(options.expectedInboundSpi)]),
      ),
    ],
  });
}

export async function runChildSaDelete(options: {
  requester: OriginalIkeRole;
  messageId: number;
  keys: Pick<IkeKeys, "skEi" | "skEr">;
  originalInitiatorIkeSender: IkeMessageSender;
  originalResponderIkeSender: IkeMessageSender;
  originalInitiatorInboundSpi: number;
  originalResponderInboundSpi: number;
}): Promise<ChildSaDeleteResult> {
  if (
    options.requester !== "original-initiator" &&
    options.requester !== "original-responder"
  ) {
    throw new TypeError("Delete requester role is invalid.");
  }
  requireLength(options.keys.skEi, 20, "SK_ei");
  requireLength(options.keys.skEr, 20, "SK_er");
  if (
    !Number.isInteger(options.messageId) ||
    options.messageId < 0 ||
    options.messageId > 0xffffffff
  ) {
    throw new RangeError("Delete Message ID must be a 32-bit value.");
  }
  validateAllocatedSpi(
    options.originalInitiatorInboundSpi,
    "original initiator inbound SPI",
  );
  validateAllocatedSpi(
    options.originalResponderInboundSpi,
    "original responder inbound SPI",
  );
  if (
    options.originalInitiatorIkeSender === options.originalResponderIkeSender
  ) {
    throw new Error(
      "IKE traffic directions require distinct sender state and keys.",
    );
  }
  const requesterIsOriginalInitiator =
    options.requester === "original-initiator";
  const requestSender = requesterIsOriginalInitiator
    ? options.originalInitiatorIkeSender
    : options.originalResponderIkeSender;
  const responseSender = requesterIsOriginalInitiator
    ? options.originalResponderIkeSender
    : options.originalInitiatorIkeSender;
  const requestKey = requesterIsOriginalInitiator
    ? options.keys.skEi
    : options.keys.skEr;
  const responseKey = requesterIsOriginalInitiator
    ? options.keys.skEr
    : options.keys.skEi;
  const requestedInboundSpi = requesterIsOriginalInitiator
    ? options.originalInitiatorInboundSpi
    : options.originalResponderInboundSpi;
  const returnedPairedInboundSpi = requesterIsOriginalInitiator
    ? options.originalResponderInboundSpi
    : options.originalInitiatorInboundSpi;
  const request = await sealChildSaDelete({
    senderRole: options.requester,
    messageId: options.messageId,
    ikeSender: requestSender,
    expectedInboundSpi: requestedInboundSpi,
  });
  const response = await responseSender.send({
    exchangeType: ExchangeType.INFORMATIONAL,
    flags: requesterIsOriginalInitiator
      ? IKE_FLAG_RESPONSE
      : IKE_FLAG_INITIATOR | IKE_FLAG_RESPONSE,
    messageId: options.messageId,
    innerPayloads: [
      payload(
        PayloadType.DELETE,
        encodeDeleteBody(3, [u32be(returnedPairedInboundSpi)]),
      ),
    ],
  });
  const openedRequest = await openIkeEncryptedMessage(
    request.message,
    requestKey,
  );
  const openedResponse = await openIkeEncryptedMessage(
    response.message,
    responseKey,
  );
  return {
    request,
    response,
    openedRequest,
    openedResponse,
    requestedInboundSpi,
    returnedPairedInboundSpi,
  };
}

function validateInputs(inputs: ChildRekeyInputs): void {
  requireLength(inputs.initiatorSpi, 8, "IKE initiator SPI");
  requireLength(inputs.responderSpi, 8, "IKE responder SPI");
  requireLength(inputs.keys.skD, 32, "SK_d");
  requireLength(inputs.keys.skEi, 20, "SK_ei");
  requireLength(inputs.keys.skEr, 20, "SK_er");
  requireLength(
    inputs.newOriginalInitiatorInboundSpi,
    4,
    "new initiator inbound SPI",
  );
  requireLength(
    inputs.newOriginalResponderInboundSpi,
    4,
    "new responder inbound SPI",
  );
  validateNonce(
    inputs.freshNonceFromExchangeInitiator,
    "rekey initiator nonce",
  );
  validateNonce(
    inputs.freshNonceFromExchangeResponder,
    "rekey responder nonce",
  );
  const newInitiatorSpi = readU32be(inputs.newOriginalInitiatorInboundSpi);
  const newResponderSpi = readU32be(inputs.newOriginalResponderInboundSpi);
  validateAllocatedSpi(newInitiatorSpi, "new initiator inbound SPI");
  validateAllocatedSpi(newResponderSpi, "new responder inbound SPI");
  validateAllocatedSpi(
    inputs.oldOriginalInitiatorInboundSpi,
    "old initiator inbound SPI",
  );
  validateAllocatedSpi(
    inputs.oldOriginalResponderInboundSpi,
    "old responder inbound SPI",
  );
  if (
    bytesEqual(
      inputs.newOriginalInitiatorInboundSpi,
      inputs.newOriginalResponderInboundSpi,
    )
  ) {
    throw new Error("The two new inbound SPIs must be distinct.");
  }
  if (
    newInitiatorSpi === inputs.oldOriginalInitiatorInboundSpi ||
    newInitiatorSpi === inputs.oldOriginalResponderInboundSpi ||
    newResponderSpi === inputs.oldOriginalInitiatorInboundSpi ||
    newResponderSpi === inputs.oldOriginalResponderInboundSpi
  ) {
    throw new Error(
      "Rekey must install fresh SPIs distinct from both old inbound SPIs.",
    );
  }
  if (inputs.originalInitiatorIkeSender === inputs.originalResponderIkeSender) {
    throw new Error(
      "IKE traffic directions require distinct sender state and keys.",
    );
  }
  if (
    !inputs.originalInitiatorIkeSender.matchesContext({
      initiatorSpi: inputs.initiatorSpi,
      responderSpi: inputs.responderSpi,
      keyWithSalt: inputs.keys.skEi,
      originalSenderIsInitiator: true,
    }) ||
    !inputs.originalResponderIkeSender.matchesContext({
      initiatorSpi: inputs.initiatorSpi,
      responderSpi: inputs.responderSpi,
      keyWithSalt: inputs.keys.skEr,
      originalSenderIsInitiator: false,
    })
  ) {
    throw new Error(
      "Declared IKE SPIs, direction, and traffic key must match both sender contexts.",
    );
  }
  const minimumMessageId =
    inputs.exchangeInitiator === "original-initiator" ? 2 : 0;
  if (
    !Number.isInteger(inputs.messageId) ||
    inputs.messageId < minimumMessageId ||
    inputs.messageId > 0xffffffff
  ) {
    throw new RangeError(
      inputs.exchangeInitiator === "original-initiator"
        ? "The original initiator's Child-SA rekey follows request Message IDs 0 and 1."
        : "The original responder's independent request Message ID must be a 32-bit value.",
    );
  }
}

function reverseSelector(selector: TrafficSelector): TrafficSelector {
  return {
    sourceAddress: { ...selector.destinationAddress },
    destinationAddress: { ...selector.sourceAddress },
    sourcePort: { ...selector.destinationPort },
    destinationPort: { ...selector.sourcePort },
    protocol: selector.protocol,
  };
}

function validateAllocatedSpi(spi: number, label: string): void {
  if (!Number.isInteger(spi) || spi < 256 || spi > 0xffffffff) {
    throw new RangeError(
      `${label} must be an allocated 32-bit value greater than 255.`,
    );
  }
}

function validateNonce(value: Uint8Array, label: string): void {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError(`${label} must contain between 16 and 256 octets.`);
  }
}
