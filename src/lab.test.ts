import { describe, expect, it } from "vitest";
import { runLab } from "./lab";

describe("learner-visible integrated evidence", () => {
  it("repeats every declared deterministic handshake and rekey field", async () => {
    const options = {
      requestedMode: "tunnel" as const,
      responderAllowsTransport: false,
      initiatorAcceptsTunnelFallback: true,
      deterministicEvidence: true,
    };
    const first = await runLab(options);
    const second = await runLab(options);
    expect(second.runToken).toBe(first.runToken);
    expect(second.fixedOracleMatched).toBe(true);
    expect(second.initRequestHash).toBe(first.initRequestHash);
    expect(second.authResponseHash).toBe(first.authResponseHash);
    expect(second.packet?.packet).toBe(first.packet?.packet);
    expect(second.rekey).toEqual(first.rekey);
    expect(second.packet?.sequence).toBe(1);
    expect(second.rekey).toMatchObject({
      oldOverlapSequence: 68,
      wrongKeyControlSequence: 69,
      retiredOldSequence: 70,
      newSequence: 1,
      wrongOldKeyControlAccepted: true,
    });
  });

  it("shows transport protecting only the upper-layer bytes", async () => {
    const run = await runLab({
      requestedMode: "transport",
      responderAllowsTransport: true,
      initiatorAcceptsTunnelFallback: false,
      deterministicEvidence: true,
    });
    expect(run.handshake.mode.establishedMode).toBe("transport");
    expect(run.packet?.protectedBytes).not.toBe(run.packet?.original);
    expect(run.packet?.protectedBytes).toBe(
      "0800e4a91234000163727970746f2d6c616221",
    );
    expect(run.packet?.reconstructedExactly).toBe(true);
  });

  it("executes protected paired-SPI deletion when tunnel fallback violates policy", async () => {
    const run = await runLab({
      requestedMode: "transport",
      responderAllowsTransport: false,
      initiatorAcceptsTunnelFallback: false,
      deterministicEvidence: true,
    });
    expect(run.handshake.mode.childState).toBe("delete-required");
    expect(run.packet).toBeNull();
    expect(run.replay).toEqual([]);
    expect(run.rekey).toBeNull();
    expect(run.fallbackDeletion).toMatchObject({
      requestMessageId: 2,
      requestSpi: "0xa1a2a3a4",
      responseSpi: "0xb1b2b3b4",
      requestPayloadType: 42,
      bothDirectionsRetired: true,
    });
  });
});
