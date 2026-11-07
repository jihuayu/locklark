// Actual popup controls -> native vault -> popup; no privileged mutation hooks.
import assert from "node:assert/strict";

export async function acceptPopupCompletion({ popup, fixture, phase, eventually, attachment, itemID }) {
  const enter = async (selector, value) => {
    await popup.click(selector);
    await popup.selectAll();
    await popup.insertText(value);
  };
  const waitDetail = async () => {
    await eventually(async () => await popup.count('#detail-view:not([hidden])') === 1,
      "Edited detail did not reopen", 30000);
  };
  const section = '#detail-fields [data-field-id^="section:"]';
  const toggle = (id) => '[data-field-id="' + id + '"] [data-action="toggle-reveal"]';
  const shown = (id) => popup.text('[data-field-id="' + id + '"] .field-value');
  phase("popup-completion:create-hidden-fields");
  await popup.click("#detail-edit");
  for (const [index, label, value] of [
    [0, "Clear this field", fixture.SaveValue],
    [1, "Retain this field", fixture.UpdateValue],
  ]) {
    await popup.click("#editor-add-custom");
    const row = '#editor-custom-fields .custom-field:nth-child(' + (index + 1) + ')';
    await enter(row + ' [data-custom-label="1"]', label);
    await popup.click(row + ' [data-custom-type="1"]');
    await popup.pressKey("ArrowDown", 40); // text -> concealed
    await popup.pressKey("Enter", 13);
    await enter(row + ' [data-custom-value="1"]', value);
  }
  await popup.click("#editor-save");
  await waitDetail();
  assert.equal(await popup.count(section), 2, "Two custom fields must persist");
  const firstID = await popup.attribute(section + ":nth-last-child(2)", "data-field-id");
  const secondID = await popup.attribute(section + ":last-child", "data-field-id");
  assert(firstID && secondID && firstID !== secondID, "Stable custom field identities required");
  phase("popup-completion:explicit-clear:open-editor");
  await popup.click("#detail-edit");
  phase("popup-completion:explicit-clear:notes");
  console.log("Popup clear controls:", JSON.stringify({
    notes: await popup.count('input[data-clear-field="notes"]'),
    custom: await popup.count('[data-custom-clear="1"]'),
  }));
  await popup.click('input[data-clear-field="notes"]');
  phase("popup-completion:explicit-clear:custom");
  await popup.click('#editor-custom-fields .custom-field:first-child [data-custom-clear="1"]');
  await popup.click("#editor-save");
  await waitDetail();
  assert.equal(await popup.count('[data-field-id="notes"]'), 0, "Explicit notes clear did not persist");
  await popup.click(toggle(firstID));
  await eventually(async () => await popup.text(toggle(firstID)) === "隐藏",
    "Cleared custom field reveal was refused");
  assert.equal(await shown(firstID), "", "Explicit custom clear did not persist");
  await popup.click(toggle(firstID));
  await popup.click(toggle(secondID));
  await eventually(async () => await shown(secondID) === fixture.UpdateValue,
    "Clearing one field lost an unrelated protected field");
  await popup.click(toggle(secondID));
  phase("popup-completion:remove-custom-field");
  await popup.click("#detail-edit");
  await popup.click('#editor-custom-fields .custom-field:first-child button');
  await popup.click("#editor-save");
  await waitDetail();
  assert.equal(await popup.count(section), 1, "Removed custom field returned after save");
  assert.equal(await popup.attribute(section, "data-field-id"), secondID,
    "Unrelated field stable identity changed");

  phase("popup-completion:attachment-upload");
  await popup.setFile("#attachment-file", attachment.sourcePath);
  await eventually(async () => await popup.count('#attachment-list [data-attachment-id]') === 1,
    "2 MiB attachment upload did not finish", 90000);
  await eventually(async () => await popup.disabled("#attachment-upload") === false,
    "Attachment upload did not settle", 30000);
  assert((await popup.text("#attachment-list"))?.includes(attachment.fileName),
    "Stored attachment metadata missing");
  phase("popup-completion:attachment-download");
  await popup.click('#attachment-list [data-action="download-attachment"]');
  await eventually(async () => {
    const status = await popup.text("#attachment-status");
    assert(status !== "附件下载未完成", "Attachment download was refused");
    return attachment.downloaded();
  }, "Downloaded attachment bytes do not match the source SHA-256", 120000);
  await eventually(async () => await popup.disabled("#attachment-upload") === false,
    "Attachment download did not settle", 30000);
  phase("popup-completion:attachment-remove");
  await popup.click('#attachment-list [data-action="remove-attachment"]');
  await eventually(async () => await popup.count('#attachment-list [data-attachment-id]') === 0,
    "Attachment removal did not persist", 30000);
  await popup.click("#detail-back");
  await popup.click('#filter-tabs [data-filter="all"]');
  await eventually(async () => await popup.disabled("#search-input") === false,
    "Vault refresh after attachment removal did not settle");
  await popup.click('#vault-list [data-item-id="' + itemID + '"]');
  await waitDetail();
  assert.equal(await popup.count('#attachment-list [data-attachment-id]'), 0,
    "Removed attachment returned after reopening");
  assert.equal(await popup.count(section), 1, "Custom field removal did not survive reopening");
  assert.equal(await popup.count('[data-field-id="notes"]'), 0, "Notes clear did not survive reopening");
  phase("popup-completion:complete");
  console.log("PASS: real popup explicit notes/custom clear, unrelated secret retention, field removal and 2 MiB attachment upload/download SHA-256/removal");
}
