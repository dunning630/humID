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
 * Add is camera first (3.0): the first time it shows what to hold up ("Start camera"),
 * afterwards the camera itself. The picker is one tap away from either: "It's something else".
 */
export async function openAdd(page) {
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".pushed, .doccam").first().waitFor({ timeout: 15_000 });
}
export async function openPicker(page) {
  await openAdd(page);
  const other = page.getByRole("button", { name: "It's something else" }).first();
  await other.waitFor({ timeout: 15_000 });
  await other.click();
  await page.locator(".pushed").getByText("What are you adding?").waitFor({ timeout: 10_000 });
}
/** From the picker: choose a kind by its title (ID · Payment card · Wallet pass · Photo · File). */
export async function pickKind(page, title) {
  await page.locator(".kinds .kind", { hasText: title }).first().click();
}
/**
 * From the picker, the ID entry (3.0 with 2.2.0's guided scan): "Which ID is it?", then the ID
 * flow's Start camera opens the outline made for that document. `which`: an ID_CHOICES title
 * (Driver's license · Passport · ID card · Another card). Nothing opens the camera before the tap.
 */
export async function chooseId(page, which) {
  await pickKind(page, /^ID/);
  await page.locator(".pushed").getByText("Which ID is it?").waitFor({ timeout: 10_000 });
  await page.locator(".kinds .kind", { hasText: which }).first().click();
  const start = page.locator(".pushed [data-start-camera]").first();
  await start.waitFor({ timeout: 10_000 });
  assert.equal(await page.locator(".doccam").count(), 0, "choosing an ID doesn't start the camera");
  await start.click();
  await page.locator(".doccam").waitFor({ timeout: 15_000 });
}
export async function pickId(page, which) { await openPicker(page); await chooseId(page, which); }
/** Photo or Payment card: the "what to show" screen the first time, then the camera. */
export async function startCamera(page) {
  const start = page.locator("[data-start-camera]").first();
  if (await start.count()) await start.click();
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
