// Real popup input and native vault round-trip; synthetic fixture values only.
import assert from "node:assert/strict";
import { acceptPopupCompletion } from "./browser_popup_completion_acceptance.mjs";

export async function acceptPopupVault({ openPopup, input, fixture, phase, observe, eventually, attachment }) {
  const popup = await openPopup();
  let lastPopup = popup;
  // The vault observer saw the item-create commit; the native item-edit commit
  // is proven by the edited title below. No native action was approved here.
  let didCommit = false;
  const fill = async (name, value) => {
    phase("popup-vault:field-" + name);
    await popup.click(
      '#editor-fields input[data-field="' + name +
      '"], #editor-fields textarea[data-field="' + name + '"]',
    );
    await popup.selectAll();
    await popup.insertText(value);
  };
  try {
    phase("popup-vault:create");
    await eventually(async () => await popup.disabled("#search-input") === false,
      "Vault refresh did not settle");
    await popup.click("#new-item-btn");
    await popup.click('#new-item-menu [data-category="login"]');
    await eventually(async () => await popup.count(
      '#editor-view:not([hidden]) input[data-field="title"]') === 1,
      "Editor did not open");
    await fill("title", "Popup native contract login");
    await fill("username", fixture.Username);
    await fill("password", fixture.Value);
    await fill("notes", fixture.SaveValue);
    await popup.click("#editor-save");
    phase("popup-vault:commit-created");
    let row;
    await eventually(async () => {
      row = observe().rows.find((item) => item.title === "Popup native contract login");
      return !!row;
    }, "Popup native save did not commit");
    didCommit = true;
    await eventually(async () => await popup.disabled("#editor-save") === false,
      "Save did not finish");
    await popup.click('#filter-tabs [data-filter="all"]');
    await eventually(async () => await popup.disabled("#search-input") === false,
      "Vault list refresh did not settle");
    const target = '#vault-list [data-item-id="' + row.id + '"]';
    await eventually(async () => await popup.count(target) === 1,
      "Saved popup item absent");
    phase("popup-vault:open-created");
    await popup.click(target);
    await eventually(async () => await popup.text("#detail-title") === "Popup native contract login",
      "Popup detail unavailable");
    const pass = '[data-field-id="password"]';
    const value = () => popup.text(pass + " .field-value");
    assert.match(await value(), /•/, "Password should be masked");
    phase("popup-vault:explicit-reveal");
    await popup.click(pass + ' [data-action="toggle-reveal"]');
    await eventually(async () => await value() === fixture.Value,
      "Native password reveal failed");
    await popup.click(pass + ' [data-action="toggle-reveal"]');
    assert(!String(await value()).includes(fixture.Value), "Hide retained visible secret");
    phase("popup-vault:edit-without-secret");
    await popup.click("#detail-edit");
    await fill("title", "Popup native contract edited");
    await popup.click("#editor-save");
    await eventually(async () => await popup.disabled("#editor-save") === false,
      "Edit save did not settle");
    await eventually(async () => await popup.text("#detail-title") === "Popup native contract edited",
      "Popup native edit failed", 30000);
    phase("popup-vault:password-preserved");
    await popup.click(pass + ' [data-action="toggle-reveal"]');
    await eventually(async () => await value() === fixture.Value,
      "Editing metadata lost password");
    await popup.click(pass + ' [data-action="toggle-reveal"]');
    phase("popup-vault:notes-preserved");
    const notes = '[data-field-id="notes"]';
    await popup.click(notes + ' [data-action="toggle-reveal"]');
    await eventually(async () => await popup.text(notes + " .field-value") === fixture.SaveValue,
      "Editing metadata lost notes");
    await popup.click(notes + ' [data-action="toggle-reveal"]');
    if (attachment)
      await acceptPopupCompletion({
        popup, input, fixture, phase, eventually, attachment, itemID: row.id,
        refresh: async () => {
          // A fresh popup is the only trusted view after the native approval.
          const fresh = await openPopup();
          lastPopup = fresh;
          await eventually(async () => await fresh.disabled("#search-input") === false,
            "Refreshed popup not ready");
          // Only the vault filter tab re-reads the vault list; #refresh
          // re-reads current-site candidates.
          await fresh.click('#filter-tabs [data-filter="all"]');
          await eventually(async () => await fresh.disabled("#search-input") === false,
            "Vault list refresh did not settle");
          const target = '#vault-list [data-item-id="' + row.id + '"]';
          await eventually(async () => await fresh.count(target) === 1,
            "Removed attachment item is not listed");
          await fresh.click(target);
          await eventually(async () => await fresh.count('#detail-view:not([hidden])') === 1 &&
            await fresh.text("#detail-title") === "Popup native contract edited",
          "Refetched item detail did not open", 30000);
          return fresh;
        },
      });
    phase("popup-vault:complete");
    console.log("PASS: real popup create, native masked detail, audited reveal, metadata edit and preserved password/notes");
    return { didCommit };
  } catch (error) {
    // The native attachment request may already have closed this popup; never
    // query the old target again, and never replace the original failure.
    const text = (selector) => popup.text(selector).catch(() => "");
    const toast = await text("#toast");
    const attachmentStatus = await text("#attachment-status");
    console.log("Popup vault diagnostic:", JSON.stringify({
      attachmentRefused: attachmentStatus === "附件下载未完成",
      attachmentDelivered: attachmentStatus === "附件已交给浏览器保存",
      saved: toast === "已保存",
      saveRefused: toast?.includes("保存未完成") === true,
      detailRefused: toast === "无法读取条目详情",
      editedCommitted: observe().rows.some((item) => item.title === "Popup native contract edited"),
    }));
    throw error;
  } finally {
    // Dismiss whichever popup is current; the original target may be gone.
    await (lastPopup || popup).dismiss().catch(() => {});
  }
}
