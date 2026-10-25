#!/usr/bin/env node
/**
 * Focused source-mutation gate for E-K-03's load-bearing protocol claims.
 *
 * Run from a clean commit. The unmodified unit/coverage/build baseline must
 * pass first. Each case changes one exact source anchor, requires its owning
 * test to fail with an assertion, restores the original bytes, and proves the
 * owner green again. A compile error, timeout, missing anchor, or dirty restore
 * is never counted as a caught mutation.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const logRoot = join(root, "test-results", "claim-mutations");
const childEnvironment = { ...process.env, CI: "1", FORCE_COLOR: "0" };

const unit = (file, title) => ({
  program: "npx",
  args: [
    "--no-install",
    "vitest",
    "run",
    file,
    "-t",
    title,
    "--reporter=verbose",
  ],
});

const mutations = [
  {
    id: "EK03-M01",
    claim: "the 64-packet replay floor rejects age equal to window size",
    file: "src/protocol/esp.ts",
    anchor: 'if (age >= window.size) return "too-old";',
    replacement: 'if (age > window.size) return "too-old";',
    owner: unit(
      "src/protocol/esp.test.ts",
      "moves its floor and refuses too-old and invalid values",
    ),
  },
  {
    id: "EK03-M02",
    claim: "the packet authenticates the receiver SPI shown on the wire",
    file: "src/protocol/esp.ts",
    anchor: "const aad = concatBytes(u32be(packetSpi), u32be(sequence));",
    replacement: "const aad = concatBytes(u32be(sa.spi), u32be(sequence));",
    owner: unit(
      "src/protocol/esp.test.ts",
      "rejects a new SPI packet sealed under the old generation key",
    ),
  },
  {
    id: "EK03-M03",
    claim:
      "ESP explicit IV allocation follows the monotonically reserved sequence",
    file: "src/protocol/esp.ts",
    anchor: "const explicitIv = u64be(BigInt(sequence));",
    replacement: "const explicitIv = u64be(0n);",
    owner: unit(
      "src/protocol/esp.test.ts",
      "sends sequence one first and matches an independent Node AES-GCM packet",
    ),
  },
  {
    id: "EK03-M04",
    claim:
      "the first Child KEYMAT slice protects initiator-to-responder traffic",
    file: "src/protocol/esp.ts",
    anchor: "keyWithSalt: options.initiatorToResponderKeymat,",
    replacement: "keyWithSalt: options.responderToInitiatorKeymat,",
    owner: unit(
      "src/protocol/esp.test.ts",
      "uses receiver-chosen SPIs and the I-to-R-first KEYMAT ordering",
    ),
  },
  {
    id: "EK03-M05",
    claim: "initial Child KEYMAT uses Ni followed by Nr",
    file: "src/protocol/ike.ts",
    anchor: "concatBytes(nonceI, nonceR),",
    replacement: "concatBytes(nonceR, nonceI),",
    owner: unit(
      "src/protocol/ike.test.ts",
      "derives initial Child KEYMAT from SK_d and Ni|Nr only, in directional order",
    ),
  },
  {
    id: "EK03-M06",
    claim: "PSK AUTH binds the peer nonce into SignedOctets",
    file: "src/protocol/ike.ts",
    anchor:
      "return concatBytes(options.firstMessage, options.peerNonce, macedId);",
    replacement: "return concatBytes(options.firstMessage, macedId);",
    owner: unit(
      "src/protocol/fixtures.test.ts",
      "pins independently recomputed project key and AUTH values",
    ),
  },
  {
    id: "EK03-M07",
    claim:
      "peer AUTH acceptance includes the expected IKE header and SA identity",
    file: "src/protocol/ike.ts",
    anchor:
      "accepted: headerMatched && identityMatched && authenticationMatched,",
    replacement: "accepted: identityMatched && authenticationMatched,",
    owner: unit(
      "src/protocol/ike.test.ts",
      "binds each AUTH value to the first message, peer nonce, and exact ID body",
    ),
  },
  {
    id: "EK03-M08",
    claim: "IKE reserves a new explicit IV independently of Message ID",
    file: "src/protocol/ike.ts",
    anchor: "this.#counter += 1n;",
    replacement: "this.#counter += 0n;",
    owner: unit(
      "src/protocol/ike-iv.test.ts",
      "does not derive the IV from Message ID or conflate request and response",
    ),
  },
  {
    id: "EK03-M09",
    claim: "transport mode is established only when the responder echoes it",
    file: "src/protocol/ike.ts",
    anchor: "if (options.responderAllowsTransport) {",
    replacement: "if (true) {",
    owner: unit(
      "src/protocol/ike.test.ts",
      "falls back to tunnel or deletes according to initiator policy",
    ),
  },
  {
    id: "EK03-M10",
    claim: "the ordered SPD returns its first matching rule",
    file: "src/protocol/spd.ts",
    anchor: "for (const [ruleIndex, rule] of rules.entries()) {",
    replacement:
      "for (const [ruleIndex, rule] of [...rules].reverse().entries()) {",
    owner: unit(
      "src/protocol/spd.test.ts",
      "makes order observable instead of choosing the most specific rule",
    ),
  },
  {
    id: "EK03-M11",
    claim:
      "Child-SA rekey KEYMAT orders fresh nonces by current exchange roles",
    file: "src/protocol/rekey.ts",
    anchor: `concatBytes(
      freshNonceFromExchangeInitiator,
      freshNonceFromExchangeResponder,
    ),`,
    replacement: `concatBytes(
      freshNonceFromExchangeResponder,
      freshNonceFromExchangeInitiator,
    ),`,
    owner: unit(
      "src/protocol/rekey.test.ts",
      "matches the independently derived fresh-nonce KEYMAT fixture",
    ),
  },
  {
    id: "EK03-M12",
    claim: "rekey sender objects belong to the declared IKE SA and direction",
    file: "src/protocol/ike.ts",
    anchor: `return (
      bytesEqual(this.#initiatorSpi, options.initiatorSpi) &&`,
    replacement: `return true || (
      bytesEqual(this.#initiatorSpi, options.initiatorSpi) &&`,
    owner: unit(
      "src/protocol/rekey.test.ts",
      "validates fresh nonces and SPIs before allocating protected-message IVs",
    ),
  },
  {
    id: "EK03-M13",
    claim: "the inbound path enforces canonical minimal ESP padding",
    file: "src/protocol/esp.ts",
    anchor: "if (padLength !== minimalPadLength) {",
    replacement: "if (false) {",
    owner: unit(
      "src/protocol/esp.test.ts",
      "refuses authenticated nonminimal and unaligned profile padding",
    ),
  },
  {
    id: "EK03-M14",
    claim: "the inbound SA is snapshotted before asynchronous authentication",
    file: "src/protocol/esp.ts",
    anchor: "const sa = unchanged.get(spi);",
    replacement: "const sa = sad.get(spi);",
    owner: unit(
      "src/protocol/esp.test.ts",
      "snapshots the caller SAD before asynchronous authentication",
    ),
  },
  {
    id: "EK03-M15",
    claim:
      "impossible replay bitmaps cannot make a seen highest value look unseen",
    file: "src/protocol/esp.ts",
    anchor: "if (!coherent) {",
    replacement: "if (false && !coherent) {",
    owner: unit("src/protocol/esp.test.ts", "rejects invalid window state"),
  },
  {
    id: "EK03-M16",
    claim:
      "IKE authenticates its full header plus SK header, not ESP's eight-octet AAD",
    file: "src/protocol/ike.ts",
    anchor: "return message.slice(0, IKE_HEADER_BYTES + 4);",
    replacement: "return message.slice(0, 8);",
    owner: unit(
      "src/protocol/ike.test.ts",
      "authenticates the IKE header plus SK header as AAD",
    ),
  },
  {
    id: "EK03-M17",
    claim: "ESP authentication succeeds before the replay window is committed",
    file: "src/protocol/esp.ts",
    anchor: `windowAfter: { ...windowBefore },
      sad: unchanged,
    };
  }

  // RFC 4303 advances anti-replay state after integrity succeeds.`,
    replacement: `windowAfter: commitReplay(windowBefore, sequence),
      sad: withReplayWindow(
        unchanged,
        spi,
        sa,
        commitReplay(windowBefore, sequence),
      ),
    };
  }

  // RFC 4303 advances anti-replay state after integrity succeeds.`,
    owner: unit(
      "src/protocol/esp.test.ts",
      "does not advance the window for a modified packet ahead of it",
    ),
  },
];

function run(program, args) {
  return spawnSync(program, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    env: childEnvironment,
  });
}

function output(result) {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function requirePass(program, args, label) {
  const result = run(program, args);
  if (result.status !== 0) {
    throw new Error(`${label} failed\n${output(result)}`);
  }
  return result;
}

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const files = [...new Set(mutations.map(({ file }) => file))];
const dirty = run("git", ["diff", "--exit-code", "HEAD", "--", ...files]);
if (dirty.status !== 0) {
  throw new Error(
    `Commit the mutation source baseline before running this gate.\n${output(dirty)}`,
  );
}
for (const mutation of mutations) {
  const source = readFileSync(join(root, mutation.file), "utf8");
  if (source.split(mutation.anchor).length !== 2) {
    throw new Error(
      `${mutation.id}: expected exactly one source anchor in ${mutation.file}`,
    );
  }
}

rmSync(logRoot, { recursive: true, force: true });
mkdirSync(logRoot, { recursive: true });
requirePass("npm", ["run", "ci"], "unmutated baseline");
console.info("baseline: unmutated copy PASSES");

for (const mutation of mutations) {
  const path = join(root, mutation.file);
  const original = readFileSync(path);
  const originalText = original.toString("utf8");
  const originalHash = hash(original);
  const mutant = originalText.replace(mutation.anchor, mutation.replacement);
  if (mutant === originalText)
    throw new Error(`${mutation.id}: empty mutation`);
  try {
    writeFileSync(path, mutant);
    const result = run(mutation.owner.program, mutation.owner.args);
    const transcript = output(result);
    writeFileSync(join(logRoot, `${mutation.id}-mutant.log`), transcript);
    const caught =
      result.status !== 0 &&
      /AssertionError|expected|Assertion failed|toEqual|toBe/.test(
        transcript,
      ) &&
      !/timed out|Timeout|Failed to load|Transform failed/.test(transcript);
    if (!caught) {
      throw new Error(
        `${mutation.id}: owning test did not catch the mutation with an assertion; see ${join("test-results", "claim-mutations", `${mutation.id}-mutant.log`)}`,
      );
    }
  } finally {
    writeFileSync(path, original);
  }
  if (hash(readFileSync(path)) !== originalHash) {
    throw new Error(`${mutation.id}: exact source restoration failed`);
  }
  const restored = requirePass(
    mutation.owner.program,
    mutation.owner.args,
    `${mutation.id} restored owner`,
  );
  writeFileSync(join(logRoot, `${mutation.id}-restored.log`), output(restored));
  console.info(`${mutation.id}: CAUGHT — ${mutation.claim}`);
}

const finalDiff = run("git", ["diff", "--exit-code", "HEAD", "--", ...files]);
if (finalDiff.status !== 0) {
  throw new Error(`Mutation sources were not restored.\n${output(finalDiff)}`);
}
console.info(`all ${mutations.length} mutation(s) caught`);
