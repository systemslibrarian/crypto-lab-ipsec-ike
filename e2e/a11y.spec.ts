import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

function collectPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error")
      errors.push(`console.error: ${message.text()}`);
  });
  return errors;
}

async function scan(page: Page, label: string): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  expect(results.violations, `${label}: axe violations`).toEqual([]);
  const geometry = await page.evaluate(() => {
    const viewport = document.documentElement.clientWidth;
    const offenders = [...document.querySelectorAll<HTMLElement>("body *")]
      .filter((element) => element.getBoundingClientRect().right > viewport + 1)
      .slice(0, 8)
      .map((element) => ({
        tag: element.tagName.toLowerCase(),
        id: element.id,
        className: element.className,
        right: Math.round(element.getBoundingClientRect().right),
      }));
    return {
      body: document.body.scrollWidth,
      document: document.documentElement.scrollWidth,
      viewport,
      offenders,
    };
  });
  expect(
    Math.max(geometry.body, geometry.document),
    `${label}: page-level horizontal overflow; ${JSON.stringify(geometry.offenders)}`,
  ).toBeLessThanOrEqual(geometry.viewport + 1);
}

for (const viewport of [
  { name: "desktop", width: 1280, height: 900 },
  { name: "narrow", width: 380, height: 900 },
]) {
  test(`WCAG A/AA, keyboard state, and reflow — ${viewport.name}`, async ({
    page,
  }) => {
    const errors = collectPageErrors(page);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.setViewportSize(viewport);
    await page.goto("./");
    await expect(page.locator("#results")).toHaveAttribute(
      "aria-busy",
      "false",
    );
    await scan(page, `${viewport.name} fresh tunnel`);

    await page.keyboard.press("Tab");
    await expect(page.locator(".skip-link")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#lesson")).toBeVisible();

    await page.getByRole("button", { name: "Load fixed evidence" }).focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#status")).toContainText(
      "explicit deterministic evidence",
    );
    await scan(page, `${viewport.name} fixed evidence`);

    await page.locator("#mode").selectOption("transport");
    await page.locator("#echo").uncheck();
    await page.locator("#fallback").uncheck();
    await page.getByRole("button", { name: "Run fresh negotiation" }).click();
    await expect(page.getByTestId("deleted-child")).toBeVisible();
    await scan(page, `${viewport.name} protected Delete`);
    expect(errors).toEqual([]);
  });
}
