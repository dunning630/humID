// What every browser check does with the 3.0 app: get past the demo gate, create a HumID,
// reach the Add picker. Kept in one place so a change to a screen's words is one edit.
import assert from "node:assert/strict";

/** The demo gate (development builds): press and hold in the check overlay. */
export async function hold(page) {
  const b = page.locator(".interrupt button.hold");
  await b.waitFor({ timeout: 20_000 });
  await b.focus(); await page.keyboard.down(" "); await page.waitForTimeout(1500); await page.keyboard.up(" ");
  await page.locator(".interrupt").waitFor({ state: "detached", timeout: 20_000 });
}

/** The recovery card's groups, as shown (never the HUMID prefix). */
export const cardGroups = (page) => page.locator(".codebox .code span").allInnerTexts();

/** Type the asked-for group back; the button then reads "I've written it down" (create) or "I've stored it safely" (You). */
export async function confirmCard(page, { wrong = false } = {}) {
  const ask = await page.locator('label[for="card-check"]').innerText();
  const n = Number(/group (\d+)/.exec(ask)[1]);
  const groups = await cardGroups(page);
  if (wrong) { await page.fill("#card-check", groups[n % groups.length]); await page.getByText(/isn't group/).waitFor(); }
  await page.fill("#card-check", groups[n - 1].toLowerCase().replace(/0/g, "O")); // as someone might write it
  await page.getByText("That matches").waitFor();
}

/** Create a HumID with the demo gate and a demo access code; ends in the empty vault. */
export async function enroll(page, { trust = true } = {}) {
  await page.getByRole("button", { name: "Create my HumID" }).click();
  if (trust) await page.getByRole("button", { name: "Trust this server" }).click({ timeout: 20_000 });
  await page.getByRole("button", { name: "Use a demo access code" }).click({ timeout: 20_000 });
  await page.getByText("Access pass ready").first().waitFor({ timeout: 30_000 });
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByText("Your body becomes the key").waitFor();
  await page.getByRole("checkbox").first().click();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  await page.getByText("Your recovery card").first().waitFor({ timeout: 30_000 });
  await confirmCard(page);
  await page.getByRole("button", { name: "I've written it down" }).click();
  await page.getByRole("heading", { name: "You're in" }).waitFor();
  await page.getByRole("button", { name: "Open my vault" }).click();
  await page.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 15_000 });
}

/** Unlock with the demo gate. */
export async function unlock(page) {
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.getByRole("heading", { name: "Vault", level: 1 }).waitFor({ timeout: 15_000 });
}

/**
 * Add (3.0.1): "What are you adding?" first, each kind of document listed; picking one opens
 * its camera at once. No camera runs before a kind is picked.
 */
export async function openAdd(page) {
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".pushed").getByText("What are you adding?").waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".doccam").count(), 0, "no camera before a kind is picked");
}
export const openPicker = openAdd;
/** The picker's row for a kind: by its data-kind key, or by its exact title. */
export function kindRow(page, which) {
  if (/^[a-z_]+$/.test(which)) return page.locator(`.kinds .kind[data-kind="${which}"]`).first();
  const t = which instanceof RegExp ? which : new RegExp(`^${which.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
  return page.locator(".kinds .kind").filter({ has: page.locator("strong", { hasText: t }) }).first();
}
/** From the picker: choose a kind (Passport · Driver's license · State ID or ID card · … · Payment card · Document · Photo · Wallet pass · File). */
export async function pickKind(page, which) { await kindRow(page, which).click(); }
const ID_TITLE = { "ID card": "State ID or ID card" };
/** From the picker, an ID kind: its outline opens at once. `which`: an ID_CHOICES title. */
export async function chooseId(page, which) {
  await pickKind(page, ID_TITLE[which] || which);
  await page.locator(".doccam").waitFor({ timeout: 15_000 });
}
export async function pickId(page, which) { await openAdd(page); await chooseId(page, which); }
/** Add ▸ File, choosing `file` (a path, or { name, mimeType, buffer }). Ends on the file's review. */
export async function addFile(page, file) {
  await openAdd(page);
  const chooser = page.waitForEvent("filechooser");
  await pickKind(page, "File");
  await (await chooser).setFiles(file);
}
/** The camera a picked kind opened. */
export async function startCamera(page) {
  await page.locator(".doccam").waitFor({ timeout: 15_000 });
}
/** Tabs. */
export const tab = (page, name) => page.locator(".tabbar button", { hasText: name }).click();
/** A You detail screen, by its hub row. */
export async function youScreen(page, row) {
  await tab(page, "You");
  await page.getByRole("heading", { name: "You", level: 1 }).waitFor();
  await page.locator(".row", { hasText: row }).first().click();
  await page.locator(".pushed").waitFor();
}
export const backOut = (page) => page.locator(".pushed [data-back]").first().click();

export { assert };
