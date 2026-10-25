import { createDecipheriv } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

async function loadFixedEvidence(page: Page): Promise<void> {
  await page.goto("./");
  await expect(page.locator("#results")).toHaveAttribute("aria-busy", "false");
  await page.getByRole("button", { name: "Load fixed evidence" }).click();
  await expect(page.locator("#status")).toContainText(
    "explicit deterministic evidence",
  );
  await expect(page.getByTestId("run-banner")).toContainText(
    "Fixed transcript oracle: PASS",
  );
}

function normalizedHex(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/^0x/, "")
    .replace(/[\s|]/g, "");
  expect(normalized).toMatch(/^[0-9a-f]+$/);
  return normalized;
}

test("the fixed run connects policy, four IKE messages, and two simplex Child SAs", async ({
  page,
}) => {
  await loadFixedEvidence(page);

  const policyRows = page.getByTestId("spd-table").locator("tbody tr");
  await expect(policyRows).toHaveCount(3);
  await expect(policyRows.nth(0)).toContainText("DISCARD");
  await expect(policyRows.nth(1)).toContainText("BYPASS");
  await expect(policyRows.nth(2)).toContainText("PROTECT");
  await expect(policyRows.nth(2)).toContainText("IP protocol 1");
  await expect(policyRows.nth(2)).not.toContainText("destination port");

  const messages = page.getByTestId("ike-flow").locator("article");
  await expect(messages).toHaveCount(4);
  const hashes = await messages.locator("code").allTextContents();
  expect(hashes).toHaveLength(4);
  expect(new Set(hashes).size).toBe(4);
  for (const hash of hashes) expect(hash.trim()).toMatch(/^[0-9a-f]{64}$/);

  const saRows = page.getByTestId("child-sa-table").locator("tbody tr");
  await expect(saRows).toHaveCount(2);
  const first = (await saRows.nth(0).locator("td").allTextContents()).map((v) =>
    v.trim(),
  );
  const second = (await saRows.nth(1).locator("td").allTextContents()).map(
    (v) => v.trim(),
  );
  expect(first[1]).not.toBe(second[1]);
  expect(first[2]).toMatch(/^[0-9a-f]{32}$/);
  expect(second[2]).toMatch(/^[0-9a-f]{32}$/);
  expect(first[3]).toMatch(/^[0-9a-f]{8}$/);
  expect(second[3]).toMatch(/^[0-9a-f]{8}$/);
  expect(`${first[2]}${first[3]}`).not.toBe(`${second[2]}${second[3]}`);
  await expect(page.getByTestId("direction-assertion")).toContainText("PASS");
});

test("the rendered ESP fields form one AES-GCM packet and decrypt to the rendered protected bytes", async ({
  page,
}) => {
  await loadFixedEvidence(page);

  const packetParts = await page
    .getByTestId("packet-strip")
    .locator("code")
    .allTextContents();
  expect(packetParts).toHaveLength(5);
  const [spiText, sequenceText, explicitIv, ciphertext, tag] =
    packetParts.map(normalizedHex);
  const facts = await page
    .locator("#packet-title + .packet-strip ~ .fact-grid .fact code")
    .allTextContents();
  expect(facts).toHaveLength(4);
  const [aad, nonce, trailer, wholePacket] = facts.map(normalizedHex);
  const protectedBytes = normalizedHex(
    await page.getByTestId("protected-bytes").innerText(),
  );

  const outboundSaCells = await page
    .getByTestId("child-sa-table")
    .locator("tbody tr")
    .first()
    .locator("td")
    .allTextContents();
  const [, receiverSpi, key, salt] = outboundSaCells.map(normalizedHex);
  expect(spiText).toBe(receiverSpi);
  expect(aad).toBe(
    `${spiText}${Number(sequenceText).toString(16).padStart(8, "0")}`,
  );
  expect(nonce).toBe(`${salt}${explicitIv}`);
  expect(wholePacket).toBe(`${aad}${explicitIv}${ciphertext}${tag}`);

  const decipher = createDecipheriv(
    "aes-128-gcm",
    Buffer.from(key, "hex"),
    Buffer.from(nonce, "hex"),
  );
  decipher.setAAD(Buffer.from(aad, "hex"));
  decipher.setAuthTag(Buffer.from(tag, "hex"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "hex")),
    decipher.final(),
  ]);
  const padLength = plaintext.at(-2)!;
  const nextHeader = plaintext.at(-1)!;
  const payload = plaintext.subarray(0, plaintext.length - padLength - 2);
  const padding = plaintext.subarray(
    plaintext.length - padLength - 2,
    plaintext.length - 2,
  );
  expect(payload.toString("hex")).toBe(protectedBytes);
  expect([...padding]).toEqual(
    Array.from({ length: padLength }, (_, index) => index + 1),
  );
  expect(nextHeader).toBe(4);
  expect(trailer).toBe(
    `${padding.toString("hex")}${padLength.toString(16).padStart(2, "0")}04`,
  );
  await expect(page.getByTestId("reconstruction-assertion")).toContainText(
    "PASS",
  );
});

test("the receiver table exposes precheck, authentication, and SAD failures without moving state", async ({
  page,
}) => {
  await loadFixedEvidence(page);
  const rows = page.getByTestId("replay-table").locator("tbody tr");
  await expect(rows).toHaveCount(7);
  const rendered = await rows.evaluateAll((items) =>
    items.map((row) =>
      [...row.querySelectorAll("td")].map(
        (cell) => cell.textContent?.trim() ?? "",
      ),
    ),
  );
  expect(rendered.map((row) => row.slice(0, 3))).toEqual([
    ["valid reordering 2, 4, 3", "ACCEPT", "0 → 4"],
    ["duplicate sequence 3", "replay-precheck", "4 → 4"],
    ["too-old sequence 2 after highest 66", "replay-precheck", "66 → 66"],
    ["unseen edge sequence 3", "ACCEPT", "66 → 66"],
    ["modified packet relabeled 1000", "authentication", "66 → 66"],
    ["valid sequence 67 after failed 1000", "ACCEPT", "66 → 67"],
    ["unknown SPI 0xdeadbeef", "sad-lookup", "— → —"],
  ]);
  await expect(page.getByTestId("rekey-assertion")).toContainText("PASS");
  await expect(
    page.locator(".fact").filter({ hasText: "Old key with the new SPI" }),
  ).toContainText("Same bytes open in the explanatory old-key view: yes");
  await expect(
    page.locator(".fact").filter({ hasText: "Old-SA sequence continuity" }),
  ).toContainText("68 → 69 → 70");
});

test("transport echo, tunnel fallback, and policy refusal produce distinct current states", async ({
  page,
}) => {
  await page.goto("./");
  await expect(page.locator("#results")).toHaveAttribute("aria-busy", "false");
  await page.locator("#mode").selectOption("transport");
  await expect(page.locator("#echo")).toBeEnabled();
  await expect(page.locator("#fallback")).toBeEnabled();

  await page.getByRole("button", { name: "Run fresh negotiation" }).click();
  await expect(page.locator("#status")).toContainText("completed");
  await expect(page.getByTestId("mode-ledger")).toContainText("transport");
  await expect(page.getByTestId("protected-bytes")).toHaveText(
    "0800e4a91234000163727970746f2d6c616221",
  );

  await page.locator("#echo").uncheck();
  await page.getByRole("button", { name: "Run fresh negotiation" }).click();
  await expect(page.locator("#status")).toContainText("completed");
  await expect(
    page
      .getByTestId("mode-ledger")
      .locator("div")
      .filter({ hasText: "Established packet mode" })
      .locator("strong"),
  ).toHaveText("tunnel");
  await expect(page.getByTestId("packet-strip")).toBeVisible();

  await page.locator("#fallback").uncheck();
  await page.getByRole("button", { name: "Run fresh negotiation" }).click();
  await expect(page.locator("#status")).toContainText("completed");
  await expect(page.getByTestId("deleted-child")).toContainText(
    "PASS: both Child-SA directions were retired",
  );
  await expect(page.getByTestId("deleted-child")).toContainText(
    "The IKE SA remains established",
  );
  await expect(page.getByTestId("packet-strip")).toHaveCount(0);
  await expect(page.getByTestId("replay-table")).toHaveCount(0);
});

test("a fresh rerun retires every prior result and publishes a new run token", async ({
  page,
}) => {
  await loadFixedEvidence(page);
  const fixedToken = await page
    .getByTestId("run-banner")
    .locator("code")
    .innerText();
  await page.getByRole("button", { name: "Run fresh negotiation" }).click();
  await expect(page.locator("#status")).toContainText("fresh learner run");
  const freshToken = await page
    .getByTestId("run-banner")
    .locator("code")
    .innerText();
  expect(freshToken).not.toBe(fixedToken);
  await expect(page.getByTestId("run-banner")).toContainText(
    "Fresh entropy: fixed transcript hashes are intentionally not expected",
  );
});
