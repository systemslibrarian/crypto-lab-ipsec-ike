import "./style.css";
import { bytesToHex } from "./protocol/bytes";
import {
  childKeymatSlicesAreDistinct,
  formatSelector,
  runLab,
  type LabOptions,
  type LabRun,
} from "./lab";

const root = document.querySelector<HTMLDivElement>("#app");
if (!root) throw new Error("Application mount point is missing.");

root.innerHTML = `
  <header class="hero">
    <nav class="topbar" aria-label="Primary">
      <a class="brand" href="https://systemslibrarian.github.io/crypto-lab/">Crypto Lab</a>
      <div class="nav-links">
        <a href="#lesson">Lesson</a>
        <a href="#evidence">Evidence</a>
        <a href="#limits">Limits</a>
      </div>
    </nav>
    <div class="hero-copy">
      <p class="eyebrow">Executable protocol notebook · E-K-03</p>
      <h1>From IKE policy to an authenticated ESP packet</h1>
      <p class="lede">Build one bounded IKEv2 exchange byte by byte, derive its two simplex Child SAs, and then make the receiver decide what to accept. Every verdict below comes from the current run.</p>
      <div class="profile-strip" aria-label="Bounded cryptographic profile">
        <span>X25519 / method 31</span><span>HMAC-SHA2-256 PRF</span><span>AES-GCM-16 / 128</span><span>64-packet replay window</span>
      </div>
    </div>
  </header>

  <main id="lesson">
    <section class="workbench" aria-labelledby="workbench-title">
      <div>
        <p class="section-kicker">Run controls</p>
        <h2 id="workbench-title">Negotiate, protect, challenge</h2>
        <p>Fresh runs generate new X25519 private scalars, nonces, SPIs and a binary teaching PSK. The fixed button is an explicit evidence seam for published and project-owned vectors.</p>
      </div>
      <form id="controls" class="controls">
        <label>Requested packet mode
          <select id="mode" name="mode">
            <option value="tunnel" selected>Tunnel (default)</option>
            <option value="transport">Transport</option>
          </select>
        </label>
        <label class="check"><input id="echo" type="checkbox" checked disabled /> Responder echoes USE_TRANSPORT_MODE</label>
        <label class="check"><input id="fallback" type="checkbox" checked disabled /> Initiator accepts tunnel fallback</label>
        <div class="actions">
          <button class="primary" type="submit">Run fresh negotiation</button>
          <button id="fixed" class="secondary" type="button">Load fixed evidence</button>
        </div>
      </form>
      <p id="status" class="status" role="status" aria-live="polite">Preparing a fresh run…</p>
    </section>

    <div id="results" aria-live="polite" aria-busy="true"></div>

    <section id="limits" class="limits" aria-labelledby="limits-title">
      <p class="section-kicker">Scope before conclusions</p>
      <h2 id="limits-title">What this lesson does not establish</h2>
      <div class="limit-grid">
        <p>This is a bounded IPv4 protocol-state lesson, not an interoperable VPN daemon. It omits certificates, EAP, IPv6, NAT traversal, fragmentation, MOBIKE, AH, ESN, kernel routing and production secret storage.</p>
        <p>Sequence-derived ESP IVs are this demo’s uniqueness construction, not an IKE-negotiated universal rule. The hand-written BigInt X25519 ladder is testable teaching arithmetic, not constant-time production code; its all-zero refusal is a declared local RFC 7748 policy, not an RFC 8031 MUST.</p>
        <p>Algorithm registry requirement levels describe implementation support, not a universal deployment recommendation. Method 31 is registered; RFC 8247 does not separately list it, so the default level is MAY.</p>
      </div>
    </section>

    <section id="evidence" class="references" aria-labelledby="references-title">
      <p class="section-kicker">Primary sources</p>
      <h2 id="references-title">Wire rules and security boundaries</h2>
      <ul>
        <li><a href="https://www.rfc-editor.org/rfc/rfc7296.html">RFC 7296 — IKEv2</a></li>
        <li><a href="https://www.rfc-editor.org/rfc/rfc4303.html">RFC 4303 — ESP</a></li>
        <li><a href="https://www.rfc-editor.org/rfc/rfc4106.html">RFC 4106 — AES-GCM for ESP</a></li>
        <li><a href="https://www.rfc-editor.org/rfc/rfc5282.html">RFC 5282 — AEAD for IKEv2</a></li>
        <li><a href="https://www.rfc-editor.org/rfc/rfc8031.html">RFC 8031 — Curve25519/X25519 for IKEv2</a></li>
        <li><a href="https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml">IANA IKEv2 parameters</a></li>
      </ul>
    </section>
  </main>
  <footer>Crypto Lab · computed in your browser · no network packets are sent</footer>
`;

const form = required<HTMLFormElement>("#controls");
const mode = required<HTMLSelectElement>("#mode");
const echo = required<HTMLInputElement>("#echo");
const fallback = required<HTMLInputElement>("#fallback");
const fixed = required<HTMLButtonElement>("#fixed");
const results = required<HTMLDivElement>("#results");
const status = required<HTMLParagraphElement>("#status");
let runGeneration = 0;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  void execute(false);
});
fixed.addEventListener("click", () => void execute(true));
for (const control of [mode, echo, fallback]) {
  control.addEventListener("change", () => {
    syncModeControls();
    runGeneration += 1;
    results.replaceChildren();
    results.setAttribute("aria-busy", "false");
    status.textContent =
      "Settings changed. Run again to compute a current result.";
  });
}

syncModeControls();
void execute(false);

async function execute(deterministicEvidence: boolean): Promise<void> {
  if (deterministicEvidence) {
    mode.value = "tunnel";
    echo.checked = true;
    fallback.checked = true;
    syncModeControls();
  }
  const generation = ++runGeneration;
  const options = readOptions(deterministicEvidence);
  setBusy(true);
  status.textContent = deterministicEvidence
    ? "Computing the explicit deterministic evidence run…"
    : "Generating fresh secrets and computing the complete run…";
  try {
    const run = await runLab(options);
    if (generation !== runGeneration) return;
    results.innerHTML = renderRun(run);
    status.textContent = `${run.source} ${run.runToken} completed. All displayed verdicts belong to this run.`;
  } catch (error) {
    if (generation !== runGeneration) return;
    results.innerHTML = `<section class="error" role="alert"><h2>Run stopped safely</h2><p>${escapeHtml(error instanceof Error ? error.message : "Unknown computation failure.")}</p><p>No partial result is being presented as current.</p></section>`;
    status.textContent = "The run stopped without publishing partial results.";
  } finally {
    if (generation === runGeneration) setBusy(false);
  }
}

function readOptions(deterministicEvidence: boolean): LabOptions {
  return {
    requestedMode: mode.value === "transport" ? "transport" : "tunnel",
    responderAllowsTransport: echo.checked,
    initiatorAcceptsTunnelFallback: fallback.checked,
    deterministicEvidence,
  };
}

function syncModeControls(): void {
  const disabled = mode.value !== "transport";
  echo.disabled = disabled;
  fallback.disabled = disabled;
}

function setBusy(busy: boolean): void {
  results.setAttribute("aria-busy", String(busy));
  for (const control of form.querySelectorAll<
    HTMLButtonElement | HTMLInputElement | HTMLSelectElement
  >("button, input, select")) {
    control.disabled = busy;
  }
  if (!busy) syncModeControls();
}

function renderRun(run: LabRun): string {
  const handshake = run.handshake;
  const packet = run.packet;
  const rekey = run.rekey;
  const directionDistinct = childKeymatSlicesAreDistinct(run);
  return `
    <section class="run-banner" data-testid="run-banner">
      <div><span class="signal"></span><strong>${escapeHtml(run.source)}</strong></div>
      <code>${escapeHtml(run.runToken)}</code>
      <p>${run.fixedOracleMatched === null ? "Fresh entropy: fixed transcript hashes are intentionally not expected." : `Fixed transcript oracle: ${verdict(run.fixedOracleMatched)}.`}</p>
    </section>

    <section class="lesson-section" aria-labelledby="policy-title">
      ${sectionNumber("01", "Policy before cryptography")}
      <h2 id="policy-title">The SPD decides; the route does something else</h2>
      <p>The ordered Security Policy Database returns its first match. Route lookup is shown beside it, but never changes the security disposition.</p>
      <div class="table-wrap"><table data-testid="spd-table"><thead><tr><th>Concrete flow</th><th>First match</th><th>SPD result</th><th>Separate route</th></tr></thead><tbody>
        ${run.policy.map((item) => `<tr><td><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.flow)}</small></td><td>${escapeHtml(item.rule)}</td><td><span class="pill ${item.action.toLowerCase()}">${item.action}</span></td><td>${escapeHtml(item.route)}</td></tr>`).join("")}
      </tbody></table></div>
      <aside class="callout"><strong>Installed selector subset</strong><code data-testid="narrowed-selector">${escapeHtml(formatSelector(handshake))}</code><p>The request carries the broader offer; the response carries this policy intersection.</p></aside>
    </section>

    <section class="lesson-section" aria-labelledby="ike-title">
      ${sectionNumber("02", "Four-message IKEv2")}
      <h2 id="ike-title">Authenticate peers and establish the first Child SA</h2>
      <div class="message-flow" data-testid="ike-flow">
        ${messageCard("1", "IKE_SA_INIT request", handshake.ikeSaInitRequest.length, run.initRequestHash, "SA → KE(31) → Nonce")}
        ${messageCard("2", "IKE_SA_INIT response", handshake.ikeSaInitResponse.length, run.initResponseHash, "SA → KE(31) → Nonce")}
        ${messageCard("3", "Encrypted IKE_AUTH request", handshake.ikeAuthRequest.message.length, run.authRequestHash, "IDi → AUTH → Child SA → TSi → TSr")}
        ${messageCard("4", "Encrypted IKE_AUTH response", handshake.ikeAuthResponse.message.length, run.authResponseHash, "IDr → AUTH → Child SA → narrowed TSi/TSr")}
      </div>
      <div class="fact-grid">
        ${fact("X25519 shared", shortHex(handshake.initiatorDh.sharedSecret), "Both peers independently agree")}
        ${fact("SKEYSEED", shortHex(handshake.keys.skeyseed), "HMAC-SHA-256(Ni | Nr, shared)")}
        ${fact("AUTHi", shortHex(handshake.initiatorAuth), "PSK AUTH binds message 1, Nr and IDi′")}
        ${fact("IKE AAD", bytesToHex(handshake.ikeAuthRequest.aad), "IKE header through the SK header")}
      </div>
      <p class="precision">The first Child SA is inside IKE_AUTH. Its proposal has no KE or INTEG transform: AEAD supplies confidentiality and integrity, and initial Child KEYMAT uses <code>prf+(SK_d, Ni | Nr)</code> without adding the X25519 secret again.</p>
    </section>

    <section class="lesson-section" aria-labelledby="child-title">
      ${sectionNumber("03", "Two simplex SAs")}
      <h2 id="child-title">The proposal SPI names the receiver’s inbound SA</h2>
      <div class="table-wrap"><table data-testid="child-sa-table"><thead><tr><th>Protected direction</th><th>Receiver-chosen SPI</th><th>AES-128 key</th><th>Salt</th></tr></thead><tbody>
        <tr><td>Original initiator → responder</td><td><code>${run.initialResponderInboundSpi}</code></td><td><code>${bytesToHex(handshake.childKeys.initiatorToResponder.slice(0, 16))}</code></td><td><code>${bytesToHex(handshake.childKeys.initiatorToResponder.slice(16))}</code></td></tr>
        <tr><td>Original responder → initiator</td><td><code>${run.initialInitiatorInboundSpi}</code></td><td><code>${bytesToHex(handshake.childKeys.responderToInitiator.slice(0, 16))}</code></td><td><code>${bytesToHex(handshake.childKeys.responderToInitiator.slice(16))}</code></td></tr>
      </tbody></table></div>
      <p class="assertion ${directionDistinct ? "pass" : "fail"}" data-testid="direction-assertion">${verdict(directionDistinct)}: the two directional 20-byte KEYMAT slices differ and are split into the separate keys and salts shown above.</p>
    </section>

    ${renderMode(run)}
    ${packet ? renderPacket(packet) : renderNoPacket(run)}
    ${packet ? renderReplay(run) : ""}
    ${rekey ? renderRekey(rekey) : ""}
  `;
}

function renderMode(run: LabRun): string {
  const mode = run.handshake.mode;
  return `<section class="lesson-section compact" aria-labelledby="mode-title">
    ${sectionNumber("04", "Mode negotiation")}
    <h2 id="mode-title">A request alone does not establish transport mode</h2>
    <div class="mode-ledger" data-testid="mode-ledger">
      ${ledger("Requested", mode.requested)}
      ${ledger("Responder echo", mode.responderEchoedTransport ? "present" : "absent")}
      ${ledger("Established packet mode", mode.establishedMode)}
      ${ledger("Child-SA state", run.fallbackDeletion ? "deleted after protected exchange" : mode.childState)}
    </div>
    <p>${escapeHtml(mode.reason)}</p>
  </section>`;
}

function renderPacket(packet: NonNullable<LabRun["packet"]>): string {
  return `<section class="lesson-section" aria-labelledby="packet-title">
    ${sectionNumber("05", "Actual ESP packet")}
    <h2 id="packet-title">Clear routing fields, authenticated header, encrypted trailer</h2>
    <div class="packet-strip" data-testid="packet-strip">
      <span class="clear"><b>SPI</b><code>${packet.spi}</code></span>
      <span class="clear"><b>Sequence</b><code>${packet.sequence}</code></span>
      <span class="clear"><b>Explicit IV</b><code>${packet.explicitIv}</code></span>
      <span class="secret"><b>Ciphertext</b><code>${packet.ciphertext}</code></span>
      <span class="tag"><b>16-byte tag</b><code>${packet.tag}</code></span>
    </div>
    <div class="fact-grid">
      ${fact("AAD", packet.aad, "Clear SPI | sequence")}
      ${fact("AEAD nonce", packet.nonce, "4-byte salt | 8-byte explicit IV")}
      ${fact("Encrypted trailer", `${packet.padding || "(empty)"} | ${packet.padLength.toString(16).padStart(2, "0")} | ${packet.nextHeader.toString(16).padStart(2, "0")}`, "padding | Pad Length | Next Header")}
      ${fact("Whole ESP packet", packet.packet, `${packet.packet.length / 2} octets on the wire`)}
    </div>
    <div class="boundary-grid">
      <article><h3>Exact protected bytes</h3><p>${escapeHtml(packet.protectedMeaning)}</p><code data-testid="protected-bytes">${packet.protectedBytes}</code></article>
      <article><h3>Clear outer IPv4 header</h3><p>${escapeHtml(packet.clearMeaning)}</p><code data-testid="outer-header">${packet.outerHeader}</code></article>
    </div>
    <p class="assertion ${packet.reconstructedExactly && packet.checksumVerified ? "pass" : "fail"}" data-testid="reconstruction-assertion">${verdict(packet.reconstructedExactly && packet.checksumVerified)}: decryption reconstructed the exact original IPv4 packet and independently verified its header checksum.</p>
  </section>`;
}

function renderReplay(run: LabRun): string {
  return `<section class="lesson-section" aria-labelledby="replay-title">
    ${sectionNumber("06", "Receiver state machine")}
    <h2 id="replay-title">Lookup, precheck, authenticate, then commit</h2>
    <p>The packets continue the one outbound SA counter after the packet above; controlled receiver views begin with stated replay-window state. An invalid tag must not move the window. An authenticated sequence is committed before this profile checks its trailer.</p>
    <div class="table-wrap"><table data-testid="replay-table"><thead><tr><th>Executed case</th><th>Verdict / stage</th><th>Highest before → after</th><th>Why</th></tr></thead><tbody>
      ${run.replay.map((item) => `<tr><td>${escapeHtml(item.label)}</td><td><span class="pill ${item.accepted ? "protect" : "discard"}">${item.accepted ? "ACCEPT" : escapeHtml(item.stage)}</span></td><td>${item.before ?? "—"} → ${item.after ?? "—"}</td><td>${escapeHtml(item.explanation)}</td></tr>`).join("")}
    </tbody></table></div>
  </section>`;
}

function renderRekey(rekey: NonNullable<LabRun["rekey"]>): string {
  const passes =
    rekey.oldAndNewAccepted &&
    rekey.wrongOldKeyControlAccepted &&
    rekey.wrongOldKeyStage === "authentication" &&
    rekey.retiredOldStage === "sad-lookup" &&
    rekey.newSequence === 1 &&
    rekey.replayWindowsStartAt === 0 &&
    rekey.deleteExchangeType === 37;
  return `<section class="lesson-section" aria-labelledby="rekey-title">
    ${sectionNumber("07", "Child-SA rekey")}
    <h2 id="rekey-title">Overlap briefly, switch generations, retire old state</h2>
    <div class="mode-ledger">
      ${ledger("New initiator inbound SPI", rekey.newInitiatorInboundSpi)}
      ${ledger("New responder inbound SPI", rekey.newResponderInboundSpi)}
      ${ledger("Protected request / response IV", `${rekey.requestIv} / ${rekey.responseIv}`)}
      ${ledger("New first ESP sequence", String(rekey.newSequence))}
    </div>
    <div class="fact-grid">
      ${fact("New I→R key / salt", `${rekey.newI2rKey} / ${rekey.newI2rSalt}`, "Fresh nonce-derived KEYMAT")}
      ${fact("New R→I key / salt", `${rekey.newR2iKey} / ${rekey.newR2iSalt}`, "Opposite directional slice")}
      ${fact("Old key with the new SPI", rekey.wrongOldKeyStage, `Same bytes open in the explanatory old-key view: ${rekey.wrongOldKeyControlAccepted ? "yes" : "no"}; the actual new-SPI SAD key rejects them`)}
      ${fact("Old-SA sequence continuity", `${rekey.oldOverlapSequence} → ${rekey.wrongKeyControlSequence} → ${rekey.retiredOldSequence}`, "One sender reserves each old-key nonce once across overlap, wrong-key control and retirement")}
      ${fact("Protected Delete request / reply", `${rekey.deleteRequestSpi} / ${rekey.deleteResponseSpi}`, "INFORMATIONAL exchange 37 names each peer’s old inbound SPI")}
      ${fact("Packet after old-SA retirement", rekey.retiredOldStage, "Retirement occurs after the protected Delete exchange")}
    </div>
    <p class="assertion ${passes ? "pass" : "fail"}" data-testid="rekey-assertion">${verdict(passes)}: old/new overlap worked, wrong-generation keying failed, retirement stopped the old SPI, and new counters/windows began at zero/one.</p>
  </section>`;
}

function renderNoPacket(run: LabRun): string {
  const deletion = run.fallbackDeletion;
  const passes =
    deletion?.requestPayloadType === 42 && deletion.bothDirectionsRetired;
  return `<section class="lesson-section stopped" data-testid="deleted-child"><h2>Packet processing stopped after a protected Delete</h2><p>Local policy rejected the tunnel fallback. The initiator sent INFORMATIONAL Message ID ${deletion?.requestMessageId ?? "—"} naming inbound SPI <code>${deletion?.requestSpi ?? "—"}</code>; the peer replied with paired inbound SPI <code>${deletion?.responseSpi ?? "—"}</code>.</p><p class="assertion ${passes ? "pass" : "fail"}">${verdict(Boolean(passes))}: both Child-SA directions were retired after the encrypted Delete exchange. The IKE SA remains established, and no ESP result is fabricated.</p></section>`;
}

function sectionNumber(number: string, label: string): string {
  return `<p class="section-kicker"><span>${number}</span>${label}</p>`;
}

function messageCard(
  number: string,
  title: string,
  length: number,
  hash: string,
  chain: string,
): string {
  return `<article><span>${number}</span><h3>${escapeHtml(title)}</h3><p>${length} octets · ${escapeHtml(chain)}</p><code title="SHA-256">${hash}</code></article>`;
}

function fact(title: string, value: string, note: string): string {
  return `<article class="fact"><h3>${escapeHtml(title)}</h3><code>${escapeHtml(value)}</code><p>${escapeHtml(note)}</p></article>`;
}

function ledger(title: string, value: string): string {
  return `<div><span>${escapeHtml(title)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function verdict(value: boolean): string {
  return value ? "PASS" : "FAIL";
}

function shortHex(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 24)}…${hex.slice(-16)}`;
}

function required<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Missing required element: ${selector}`);
  return element;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;",
    };
    return entities[character]!;
  });
}
