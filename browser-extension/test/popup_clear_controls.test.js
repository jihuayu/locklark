const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

const flush = () => new Promise((resolve) => setImmediate(resolve));
const ID = "b".repeat(32);
const REV = "c".repeat(64);
const NEXT = "9".repeat(64);

function element() {
  return {
    textContent: "",
    value: "",
    checked: false,
    disabled: false,
    hidden: false,
    type: "",
    className: "",
    dataset: {},
    style: {},
    attributes: {},
    children: [],
    parent: null,
    classList: { add() {}, remove() {}, toggle() {} },
    listeners: new Map(),
    addEventListener(type, callback) {
      this.listeners.set(type, callback);
    },
    append(...children) {
      for (const child of children) {
        if (child && typeof child === "object") child.parent = this;
        this.children.push(child);
      }
    },
    prepend(child) {
      if (child && typeof child === "object") child.parent = this;
      this.children.unshift(child);
    },
    replaceChildren(...children) {
      this.children = [];
      this.append(...children);
    },
    querySelector(selector) {
      const match = /^\[data-([a-z-]+)="([^"]*)"\]$/.exec(selector);
      if (!match) return null;
      const key = match[1].replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      for (const child of this.children) {
        if (!child || typeof child !== "object") continue;
        if (String(child.dataset?.[key]) === match[2]) return child;
        const nested = child.querySelector ? child.querySelector(selector) : null;
        if (nested) return nested;
      }
      return null;
    },
    remove() {
      if (!this.parent) return;
      const index = this.parent.children.indexOf(this);
      if (index >= 0) this.parent.children.splice(index, 1);
    },
    click() {
      this.clicked = true;
    },
    focus() {},
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null;
    },
    removeAttribute(name) {
      delete this.attributes[name];
    },
  };
}

function detailDocument() {
  return {
    id: ID,
    revision: REV,
    category: "login",
    title: "Login",
    urls: [],
    tags: [],
    notes: "",
    has_notes: true,
    fields: [
      { id: "username", label: "用户名", type: "text", value: "ada", concealed: false },
      { id: "password", label: "密码", type: "concealed", value: "", concealed: true, has_value: true, revealable: true },
      { id: "notes", label: "备注", type: "concealed", value: "", concealed: true, has_value: true, revealable: true },
      // publicDetail also projects section fields into the flat list with their
      // qualified stable key; the editor must not render them twice.
      {
        id: "section:sec1:f1",
        label: "Code",
        type: "concealed",
        value: "",
        concealed: true,
        revealable: true,
        section_id: "sec1",
        section_title: "Recovery",
      },
      {
        id: "section:sec1:f2",
        label: "Visible",
        type: "text",
        value: "plain",
        concealed: false,
        section_id: "sec1",
        section_title: "Recovery",
      },
    ],
    sections: [
      {
        id: "sec1",
        title: "Recovery",
        fields: [
          { id: "f1", label: "Code", type: "concealed", value: "", concealed: true, purpose: "totp" },
          { id: "f2", label: "Visible", type: "text", value: "plain" },
        ],
      },
    ],
  };
}

function harness() {
  const elements = new Map();
  const requests = [];
  let pagehide = null,
    poll = null;
  const document = {
    body: { dataset: { vault: "1" } },
    visibilityState: "visible",
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector);
    },
    querySelectorAll(selector) {
      if (selector === "#filter-tabs [data-filter]")
        return [this.querySelector("#tab-passkeys")];
      return [];
    },
    createElement: element,
    createTextNode: (text) => ({ textContent: text }),
    addEventListener() {},
  };
  document.querySelector("#tab-passkeys").dataset.filter = "passkeys";
  const context = {
    LocklarkCore: core,
    document,
    navigator: { clipboard: { writeText: async () => {} } },
    chrome: {
      runtime: {
        sendMessage(message) {
          return new Promise((resolve, reject) =>
            requests.push({ message, resolve, reject }),
          );
        },
      },
    },
    crypto: webcrypto,
    Blob,
    URL,
    Uint8Array,
    setTimeout,
    clearTimeout,
    setInterval(callback) {
      poll = callback;
      return 0;
    },
    clearInterval: () => {},
    addEventListener(type, callback) {
      if (type === "pagehide") pagehide = callback;
    },
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8"),
    context,
  );
  return {
    requests,
    pagehide: () => pagehide?.(),
    poll: () => poll?.(),
    el: (selector) => context.document.querySelector(selector),
    take(type) {
      const call = requests.find((r) => !r.taken && r.message.type === type);
      assert.ok(call, "missing " + type + " request");
      call.taken = true;
      return call;
    },
    async openEditor(detail = detailDocument()) {
      this.take("state").resolve({
        connected: true,
        status: "ready",
        origin: "https://example.test/",
        candidates: [],
        vaultItems: [
          {
            id: ID,
            revision: REV,
            category: "login",
            title: "Login",
            urls: ["https://example.test/"],
            tags: [],
            favorite: false,
          },
        ],
        generatorDefaults: { mode: "random", length: 24 },
        attachmentsSupported: true,
      });
      await flush();
      this.el("#vault-list").children[0].listeners.get("click")();
      this.take("item-get").resolve({ detail, connected: true });
      await flush();
      this.el("#detail-edit").listeners.get("click")();
      await flush();
    },
  };
}

function editorField(h, name) {
  return h
    .el("#editor-fields")
    .children.find((child) => child.dataset && child.dataset.field === name);
}

test("editor offers explicit clear for masked notes and masked custom fields", async () => {
  const h = harness();
  await h.openEditor();

  const clearNotes = editorField(h, "clear_notes");
  assert.ok(clearNotes, "clear-notes control must render from the unfiltered detail");
  const clearNotesInput = clearNotes.children[1];
  assert.equal(clearNotesInput.type, "checkbox");
  assert.equal(clearNotesInput.dataset.clearField, "notes");
  const notesInput = editorField(h, "notes").children[1];
  assert.equal(notesInput.value, "", "masked notes are never copied into the editor");

  const rows = h.el("#editor-custom-fields").children;
  const maskedRow = rows.find((row) => row.dataset.fieldId === "f1");
  const visibleRow = rows.find((row) => row.dataset.fieldId === "f2");
  assert.ok(maskedRow && visibleRow, "both masked and visible section rows render");
  assert.equal(rows.length, 2, "publicDetail flattening must not duplicate section rows");
  assert.equal(
    h.el("#editor-custom-fields").children.filter(
      (row) => row.querySelector('[data-custom-clear="1"]'),
    ).length,
    1,
    "one clear control per stored field",
  );
  const maskedClear = maskedRow.querySelector('[data-custom-clear="1"]');
  assert.ok(maskedClear, "masked custom field needs an explicit clear checkbox");
  assert.equal(maskedClear.dataset.clearField, "section:sec1:f1");
  assert.equal(
    visibleRow.querySelector('[data-custom-clear="1"]'),
    null,
    "visible fields have no clear checkbox",
  );
  assert.equal(
    maskedRow.querySelector('[data-custom-value="1"]').value,
    "",
    "masked value is not copied into the row",
  );
  assert.equal(
    visibleRow.querySelector('[data-custom-value="1"]').value,
    "plain",
    "visible value is editable",
  );

  // Explicit checks produce the forwarded contract clear list.
  maskedClear.checked = true;
  clearNotesInput.checked = true;
  h.el("#editor-save").listeners.get("click")();
  await flush();
  const save = h.take("item-save");
  const item = save.message.item;
  assert.deepEqual(Array.from(item.clear_fields), ["section:sec1:f1", "notes"]);
  assert.equal(JSON.stringify(item).includes("••"), false, "bullets never reach the wire");
  const section = item.sections.find((entry) => entry.id === "sec1");
  assert.equal(section.fields.find((field) => field.id === "f1").value, "");
  assert.equal(section.fields.find((field) => field.id === "f2").value, "plain");
  const mutation = core.itemToNativeMutation(item, {
    original: detailDocument(),
  });
  assert.deepEqual(Array.from(mutation.clear_fields), ["section:sec1:f1", "notes"]);
  assert.equal(mutation.notes, "");
  assert.equal(mutation.sections.length, 1);
  assert.equal(mutation.sections[0].id, "sec1");
  assert.equal(mutation.sections[0].fields.find((field) => field.id === "f1").value, "");
  assert.equal(mutation.sections[0].fields.find((field) => field.id === "f2").value, "plain");

  save.resolve({ saved: { item_id: ID, revision: NEXT } });
  await flush();
  const refreshed = h.take("item-get");
  refreshed.resolve({
    detail: {
      ...detailDocument(),
      revision: NEXT,
      notes: "",
      has_notes: false,
      fields: detailDocument().fields.filter(
        (field) => field.id !== "notes" && field.id !== "section:sec1:f1",
      ),
      sections: [
        { id: "sec1", title: "Recovery", fields: [{ id: "f2", label: "Visible", type: "text", value: "plain" }] },
      ],
    },
  });
  await flush();
  assert.equal(
    h.el("#detail-unavailable").hidden,
    true,
    "cleared targets must not trigger the unsupported notice",
  );
});

test("removing the single stored custom row sends an empty section list", async () => {
  const h = harness();
  await h.openEditor();
  const rows = h.el("#editor-custom-fields").children;
  const maskedRow = rows.find((row) => row.dataset.fieldId === "f1");
  const remove = maskedRow.children.find(
    (child) => child.textContent === "移除" && child.listeners?.has("click"),
  );
  assert.ok(remove, "row exposes a remove control");
  remove.listeners.get("click")();
  const visibleRow = h
    .el("#editor-custom-fields")
    .children.find((row) => row.dataset.fieldId === "f2");
  visibleRow.children
    .find((child) => child.textContent === "移除" && child.listeners?.has("click"))
    .listeners.get("click")();
  h.el("#editor-save").listeners.get("click")();
  await flush();
  const save = h.take("item-save");
  assert.deepEqual(Array.from(save.message.item.sections), [], "removed rows remove all supplied fields");
  save.resolve({ saved: { item_id: ID, revision: NEXT } });
  await flush();
  h.take("item-get").resolve({ detail: { ...detailDocument(), revision: NEXT } });
  await flush();
});

test("clear checkbox with typed text refuses to save and names the conflict", async () => {
  const h = harness();
  await h.openEditor();
  const clearNotes = editorField(h, "clear_notes");
  const notesInput = editorField(h, "notes").children[1];
  notesInput.value = "new note text";
  clearNotes.children[1].checked = true;
  h.el("#editor-save").listeners.get("click")();
  await flush();
  assert.equal(
    h.requests.filter((request) => request.message.type === "item-save").length,
    0,
    "conflicting clear never reaches the host",
  );
  assert.match(h.el("#toast").textContent, /清空备注/);
});

test("host that keeps cleared values shows an actionable unsupported notice", async () => {
  const h = harness();
  await h.openEditor();
  const clearNotes = editorField(h, "clear_notes");
  clearNotes.children[1].checked = true;
  h.el("#editor-save").listeners.get("click")();
  await flush();
  const save = h.take("item-save");
  save.resolve({ saved: { item_id: ID, revision: NEXT } });
  await flush();
  const refreshed = h.take("item-get");
  // An old host silently preserves the masked notes entry.
  refreshed.resolve({
    detail: { ...detailDocument(), revision: NEXT },
  });
  await flush();
  assert.equal(h.el("#detail-unavailable").hidden, false);
  assert.match(h.el("#detail-unavailable").textContent, /升级原生宿主/);
});

async function settle(turns = 16) {
  for (let i = 0; i < turns; i++) await flush();
}
function detailWithAttachments() {
  return {
    ...detailDocument(),
    attachments: [
      {
        id: "e".repeat(32),
        file_name: "notes.txt",
        size: 1,
        sha256: "a".repeat(64),
      },
    ],
  };
}

async function openDetail(h, detail, options = {}) {
  h.take("state").resolve({
    connected: true,
    status: "ready",
    origin: "https://example.test/",
    candidates: [],
    vaultItems: [
      {
        id: ID,
        revision: REV,
        category: "login",
        title: "Login",
        urls: ["https://example.test/"],
        tags: [],
        favorite: false,
      },
    ],
    generatorDefaults: { mode: "random", length: 24 },
    attachmentsSupported: true,
    ...(options.state || {}),
  });
  await settle();
  h.el("#vault-list").children[0].listeners.get("click")();
  h.take("item-get").resolve({ detail, connected: true, ...(options.reply || {}) });
  await settle();
}

function shown(h) {
  return h
    .el("#detail-fields")
    .children.map((row) =>
      row.children.map((child) => child.textContent).join("|"),
    )
    .join(" ");
}
async function waitFor(check, turns = 2000) {
  for (let i = 0; i < turns; i++) {
    const value = check();
    if (value) return value;
    await flush();
  }
  return check();
}

const ATTACH = "e".repeat(32);
const BODY = new Uint8Array([7]);
const BODY_SHA = require("node:crypto")
  .createHash("sha256")
  .update(BODY)
  .digest("hex");

async function openDetailWithAttachment(h, sha = BODY_SHA) {
  const detail = {
    ...detailDocument(),
    attachments: [
      { id: ATTACH, file_name: "notes.txt", size: BODY.length, sha256: sha },
    ],
  };
  await openDetail(h, detail);
  return detail;
}

function downloadButton(h) {
  const row = h.el("#attachment-list").children[0];
  return row.children.find(
    (child) => child.dataset.action === "download-attachment",
  );
}

function readReply(id, attachment) {
  return {
    attachmentData: {
      item_id: id,
      revision: REV,
      attachment,
      offset: 0,
      next_offset: BODY.length,
      done: true,
      data: core.base64Encode(BODY),
    },
  };
}

function controls(h) {
  const row = h.el("#attachment-list").children[0];
  return {
    upload: h.el("#attachment-upload").disabled,
    download: row.children.find(
      (child) => child.dataset.action === "download-attachment",
    ).disabled,
    remove: row.children.find(
      (child) => child.dataset.action === "remove-attachment",
    ).disabled,
  };
}

const enabled = { upload: false, download: false, remove: false };

test("entering the editor cancels an in-flight upload and masks revealed values", async () => {
  const h = harness();
  await openDetail(h, detailWithAttachments());

  const passwordRow = h
    .el("#detail-fields")
    .children.find((row) => row.dataset.fieldId === "password");
  passwordRow.children[2].listeners.get("click")();
  const revealCall = await waitFor(() => h.requests.find((r) => r.message.type === "reveal-field"));
  revealCall.taken = true;
  revealCall.resolve({
    revealedField: {
      field: "password",
      value: "S3cret-Value",
      revision: REV,
      expires_in_seconds: 30,
      copied: false,
    },
  });
  await waitFor(() => /S3cret-Value/.test(shown(h)));
  assert.match(shown(h), /S3cret-Value/, "revealed value is visible before editing");

  const file = {
    name: "big.bin",
    size: 5,
    type: "application/octet-stream",
    arrayBuffer: async () => new Uint8Array([1, 2, 3, 4, 5]).buffer,
  };
  h.el("#attachment-file").listeners.get("change")({
    target: { files: [file], value: "" },
  });
  const begin = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-begin"),
  );
  assert.ok(begin, "upload begins once the file hash is ready");
  begin.taken = true;
  begin.resolve({
    attachmentTransfer: {
      transfer_id: "d".repeat(32),
      offset: 0,
      size: 5,
      expires_in_seconds: 120,
    },
  });
  const heldChunk = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-chunk"),
  );
  heldChunk.taken = true;

  h.el("#detail-edit").listeners.get("click")();
  await flush();
  assert.equal(
    h.requests.some((request) => request.message.type === "attachment-cancel"),
    true,
    "entering the editor cancels the active transfer",
  );
  assert.equal(h.el("#detail-view").hidden, true);
  assert.equal(h.el("#editor-view").hidden, false);
  assert.equal(
    h.el("#editor-custom-fields").children.length,
    2,
    "editor keeps lastDetail metadata after the cancel",
  );
  assert.doesNotMatch(
    shown(h),
    /S3cret-Value/,
    "hidden detail DOM no longer holds the revealed value",
  );

  heldChunk.resolve({
    attachmentTransfer: {
      transfer_id: "d".repeat(32),
      offset: 5,
      size: 5,
      expires_in_seconds: 120,
    },
  });
  await settle(8);
  assert.equal(
    h.requests.some((request) => request.message.type === "attachment-commit"),
    false,
    "late continuation cannot commit after leaving the detail view",
  );
  assert.equal(
    h.requests.filter((request) => request.message.type === "attachment-chunk")
      .length,
    1,
    "no further chunks are emitted",
  );
  assert.equal(h.el("#editor-view").hidden, false, "editor stays in front");
  assert.equal(h.el("#detail-view").hidden, true);
  h.pagehide();
  await flush();
});

test("completed download re-enables upload, download and remove", async () => {
  const h = harness();
  await openDetailWithAttachment(h);
  downloadButton(h).listeners.get("click")();
  const read = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-read"),
  );
  read.taken = true;
  read.resolve(
    readReply(ID, { id: ATTACH, file_name: "notes.txt", size: 1, sha256: BODY_SHA }),
  );
  await waitFor(() => controls(h).upload === false);
  assert.deepEqual(controls(h), enabled);
});

test("failed download re-enables the controls and reports failure", async () => {
  const h = harness();
  await openDetailWithAttachment(h, "b".repeat(64));
  downloadButton(h).listeners.get("click")();
  const read = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-read"),
  );
  read.taken = true;
  read.resolve(
    readReply(ID, { id: ATTACH, file_name: "notes.txt", size: 1, sha256: "b".repeat(64) }),
  );
  await waitFor(() => h.el("#attachment-status").textContent.includes("下载未完成"));
  assert.deepEqual(controls(h), enabled, "failures re-enable every control");
});

test("stale generation finalizer cannot clear a newer busy state", async () => {
  const h = harness();
  await openDetailWithAttachment(h);
  downloadButton(h).listeners.get("click")();
  const oldRead = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-read"),
  );
  oldRead.taken = true;
  h.el("#detail-edit").listeners.get("click")();
  await flush();
  h.el("#editor-back").listeners.get("click")();
  await flush();
  downloadButton(h).listeners.get("click")();
  const newRead = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-read"),
  );
  assert.ok(newRead, "second download starts in the new generation");
  newRead.taken = true;
  assert.equal(controls(h).upload, true, "new download owns the busy state");
  oldRead.resolve(
    readReply(ID, { id: ATTACH, file_name: "notes.txt", size: 1, sha256: BODY_SHA }),
  );
  await settle(12);
  assert.equal(
    controls(h).upload,
    true,
    "stale finalizer must not re-enable controls",
  );
  newRead.resolve(
    readReply(ID, { id: ATTACH, file_name: "notes.txt", size: 1, sha256: BODY_SHA }),
  );
  await waitFor(() => controls(h).upload === false);
  assert.deepEqual(controls(h), enabled);
});

function uploadFile(name = "big.bin") {
  return {
    name,
    size: 5,
    type: "application/octet-stream",
    arrayBuffer: async () => new Uint8Array([1, 2, 3, 4, 5]).buffer,
  };
}

function startUpload(h, file = uploadFile()) {
  h.el("#attachment-file").listeners.get("change")({
    target: { files: [file], value: "" },
  });
}

const beginReply = (transferId) => ({
  attachmentTransfer: {
    transfer_id: transferId,
    offset: 0,
    size: 5,
    expires_in_seconds: 120,
  },
});

const chunkReply = (transferId) => ({
  attachmentTransfer: {
    transfer_id: transferId,
    offset: 5,
    size: 5,
    expires_in_seconds: 120,
  },
});

test("late begin from an old generation cannot cancel or clear the new upload", async () => {
  const h = harness();
  await openDetailWithAttachment(h);
  startUpload(h, uploadFile("old.bin"));
  const oldBegin = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-begin"),
  );
  assert.ok(oldBegin);
  oldBegin.taken = true;
  // Leave the detail view, then start a new upload generation.
  h.el("#detail-edit").listeners.get("click")();
  await flush();
  h.el("#editor-back").listeners.get("click")();
  await flush();
  startUpload(h, uploadFile("new.bin"));
  const newBegin = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-begin"),
  );
  assert.ok(newBegin, "new upload begins");
  newBegin.taken = true;
  newBegin.resolve(beginReply("d".repeat(32)));
  const newChunk = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-chunk"),
  );
  assert.ok(newChunk);
  assert.equal(newChunk.message.transfer_id, "d".repeat(32));
  newChunk.taken = true;

  // The old begin answers late with its own token: only that token may be
  // cancelled, and the new operation keeps its busy state.
  oldBegin.resolve(beginReply("f".repeat(32)));
  await settle(12);
  assert.equal(
    h.requests.some(
      (request) =>
        request.message.type === "attachment-cancel" &&
        request.message.transfer_id === "d".repeat(32),
    ),
    false,
    "old generation must not cancel the new token",
  );
  assert.equal(
    h.requests.some(
      (request) =>
        request.message.type === "attachment-cancel" &&
        request.message.transfer_id === "f".repeat(32),
    ),
    true,
    "the late begin cancels only its own token",
  );
  assert.equal(controls(h).upload, true, "new upload stays busy");

  newChunk.resolve(chunkReply("d".repeat(32)));
  const commit = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-commit"),
  );
  assert.ok(commit, "new upload commits with its own token");
  assert.equal(commit.message.transfer_id, "d".repeat(32));
  commit.taken = true;
  commit.resolve({
    attachmentSaved: {
      item_id: ID,
      revision: NEXT,
      attachment: { id: ATTACH, file_name: "new.bin", size: 5, sha256: BODY_SHA },
    },
  });
  const refresh = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "item-get"),
  );
  refresh.taken = true;
  refresh.resolve({ detail: { ...detailDocument(), revision: NEXT } });
  await waitFor(() => h.el("#attachment-status").textContent.includes("已添加"));
});

test("rejected old download cannot overwrite the new operation status", async () => {
  const h = harness();
  await openDetailWithAttachment(h);
  downloadButton(h).listeners.get("click")();
  const oldRead = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-read"),
  );
  oldRead.taken = true;
  h.el("#detail-edit").listeners.get("click")();
  await flush();
  h.el("#editor-back").listeners.get("click")();
  await flush();
  downloadButton(h).listeners.get("click")();
  const newRead = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-read"),
  );
  newRead.taken = true;
  oldRead.reject(Error("native refused"));
  await settle(12);
  assert.equal(
    h.el("#attachment-status").textContent,
    "正在下载附件…",
    "old failure must not overwrite the new status",
  );
  newRead.resolve(
    readReply(ID, { id: ATTACH, file_name: "notes.txt", size: 1, sha256: BODY_SHA }),
  );
  await waitFor(() =>
    h.el("#attachment-status").textContent.includes("交给浏览器保存"),
  );
});

test("unknown commit outcome is reported as unconfirmed, not unsaved", async () => {
  const h = harness();
  await openDetailWithAttachment(h);
  startUpload(h);
  const begin = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-begin"),
  );
  begin.taken = true;
  begin.resolve(beginReply("d".repeat(32)));
  const chunk = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-chunk"),
  );
  chunk.taken = true;
  chunk.resolve(chunkReply("d".repeat(32)));
  const commit = await waitFor(() =>
    h.requests.find((r) => !r.taken && r.message.type === "attachment-commit"),
  );
  commit.taken = true;
  commit.reject(Error("disconnected"));
  await waitFor(() =>
    h.el("#attachment-status").textContent.includes("附件保存结果未确认"),
  );
  assert.match(
    h.el("#attachment-status").textContent,
    /刷新核实/,
    "unknown commit outcome stays actionable",
  );
  assert.equal(controls(h).upload, false, "controls recover after the failure");
});

const PASSKEY_CRED = core.base64URLEncode(new Uint8Array(32).fill(3));
function passkeyDetail(overrides = {}) {
  return {
    ...detailDocument(),
    has_passkey: true,
    passkey: {
      credential_id: PASSKEY_CRED,
      rp_id: "example.test",
      user_name: "ada@example.test",
      display_name: "Ada Lovelace",
    },
    ...overrides,
  };
}

test("passkey detail shows safe metadata and cancel sends no removal RPC", async () => {
  const h = harness();
  await openDetail(h, passkeyDetail(), {
    state: { passkeyManagementSupported: true },
    reply: { passkeyManagementSupported: true },
  });
  assert.equal(h.el("#passkey-detail").hidden, false);
  assert.equal(h.el("#passkey-rp").textContent, "example.test");
  assert.equal(h.el("#passkey-username").textContent, "ada@example.test");
  assert.equal(h.el("#passkey-display-name").textContent, "Ada Lovelace");
  assert.equal(h.el("#passkey-remove").hidden, false);
  assert.match(shown(h), /ada/);

  h.el("#passkey-remove").listeners.get("click")();
  assert.equal(h.el("#passkey-remove-confirm").hidden, false);
  assert.equal(h.el("#passkey-remove-cancel").hidden, false);
  assert.equal(h.el("#passkey-remove-warning").hidden, false);
  assert.equal(
    h.requests.some((request) => request.message.type === "passkey-remove"),
    false,
    "opening confirmation must not send an RPC",
  );
  h.el("#passkey-remove-cancel").listeners.get("click")();
  assert.equal(h.el("#passkey-remove-confirm").hidden, true);
  assert.equal(
    h.requests.some((request) => request.message.type === "passkey-remove"),
    false,
    "explicit cancel must not send an RPC",
  );
});

test("confirmed passkey removal sends exact selector and keeps the login", async () => {
  const h = harness();
  await openDetail(h, passkeyDetail(), {
    state: { passkeyManagementSupported: true },
    reply: { passkeyManagementSupported: true },
  });
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  const remove = h.take("passkey-remove");
  assert.deepEqual(Object.keys(remove.message).sort(), [
    "credential_id", "id", "revision", "type",
  ]);
  assert.equal(remove.message.id, ID);
  assert.equal(remove.message.revision, REV);
  assert.equal(remove.message.credential_id, PASSKEY_CRED);
  remove.resolve({
    connected: true,
    passkeyManagementSupported: true,
    passkeyRemoved: { item_id: ID, revision: NEXT, credential_id: PASSKEY_CRED },
  });
  await settle();
  const list = h.take("vault-search");
  assert.equal(list.message.passkeysOnly, false);
  list.resolve({
    connected: true,
    passkeyManagementSupported: true,
    vaultItems: [{
      id: ID, revision: NEXT, category: "login", title: "Login",
      urls: ["https://example.test/"], tags: [], favorite: false,
    }],
  });
  await settle();
  const refreshed = h.take("item-get");
  assert.equal(refreshed.message.revision, NEXT);
  refreshed.resolve({
    connected: true,
    passkeyManagementSupported: true,
    detail: { ...detailDocument(), revision: NEXT, has_passkey: false },
  });
  await settle();
  assert.equal(h.el("#passkey-detail").hidden, true);
  assert.match(shown(h), /ada/, "login username/password fields remain after passkey removal");
  assert.equal(h.el("#vault-list").children[0].dataset.itemId, ID);
});

test("old host shows explicit passkey upgrade notice without a remove control", async () => {
  const h = harness();
  await openDetail(h, { ...detailDocument(), has_passkey: true }, {
    state: { passkeyManagementSupported: false },
    reply: { passkeyManagementSupported: false },
  });
  assert.equal(h.el("#passkey-detail").hidden, false);
  assert.match(h.el("#passkey-detail-unsupported").textContent, /升级原生宿主/);
  assert.equal(h.el("#passkey-remove").hidden, true);
  assert.equal(
    h.requests.some((request) => request.message.type === "passkey-remove"),
    false,
  );
});

test("passkey filter is server-owned and a stale query cannot replace newer rows", async () => {
  const h = harness();
  const rowA = {
    id: "1".repeat(32), revision: "2".repeat(64), category: "login",
    title: "Old passkey", passkey: {
      credential_id: PASSKEY_CRED, rp_id: "old.test", user_name: "old", display_name: "Old",
    }, urls: [], tags: [], favorite: false,
  };
  const rowB = {
    id: "3".repeat(32), revision: "4".repeat(64), category: "login",
    title: "New passkey", passkey: {
      credential_id: core.base64URLEncode(new Uint8Array(32).fill(4)),
      rp_id: "new.test", user_name: "new", display_name: "New",
    }, urls: [], tags: [], favorite: false,
  };
  h.take("state").resolve({
    connected: true,
    status: "ready",
    origin: "https://example.test/",
    candidates: [],
    vaultItems: [rowA],
    passkeyManagementSupported: true,
    generatorDefaults: { mode: "random", length: 24 },
  });
  await settle();
  h.el("#tab-passkeys").listeners.get("click")();
  const first = h.take("vault-search");
  assert.equal(first.message.passkeysOnly, true);
  h.el("#search-input").value = "new";
  h.el("#search-input").listeners.get("input")({
    target: h.el("#search-input"),
  });
  await new Promise((resolve) => setTimeout(resolve, 160));
  const second = h.take("vault-search");
  assert.equal(second.message.passkeysOnly, true);
  assert.equal(second.message.query, "new");
  second.resolve({
    connected: true,
    passkeyManagementSupported: true,
    vaultItems: [rowB],
  });
  await settle();
  assert.equal(h.el("#vault-list").children[0].dataset.itemId, rowB.id);
  first.resolve({
    connected: true,
    passkeyManagementSupported: true,
    vaultItems: [rowA],
  });
  await settle();
  assert.equal(
    h.el("#vault-list").children[0].dataset.itemId,
    rowB.id,
    "stale response must not overwrite the newer filter result",
  );
});

test("late passkey removal cannot overwrite a new locked view", async () => {
  const h = harness();
  await openDetail(h, passkeyDetail(), {
    state: { passkeyManagementSupported: true },
    reply: { passkeyManagementSupported: true },
  });
  const itemGets = h.requests.filter((request) => request.message.type === "item-get").length;
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  const remove = h.take("passkey-remove");
  h.el("#lock-btn").listeners.get("click")();
  const lock = h.take("lock");
  lock.resolve({ connected: false, status: "已锁定", candidates: [] });
  await settle();
  remove.resolve({
    connected: true,
    passkeyManagementSupported: true,
    passkeyRemoved: { item_id: ID, revision: NEXT, credential_id: PASSKEY_CRED },
  });
  await settle();
  assert.equal(h.el("#passkey-detail").hidden, true);
  assert.equal(
    h.requests.filter((request) => request.message.type === "item-get").length,
    itemGets,
    "stale success must not refresh or reopen the detail view",
  );
});

test("uncertain passkey removal suppresses retry until a fresh detail refresh", async () => {
  const h = harness();
  await openDetail(h, passkeyDetail(), {
    state: { passkeyManagementSupported: true },
    reply: { passkeyManagementSupported: true },
  });
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  const remove = h.take("passkey-remove");
  remove.resolve({
    connected: true,
    passkeyManagementSupported: true,
    status: "Passkey 删除结果未确认，请刷新核实",
    passkeyRemoveError: "uncertain",
  });
  await settle();
  assert.match(h.el("#passkey-status").textContent, /结果未确认/);
  assert.equal(h.el("#passkey-remove").hidden, true);
  assert.equal(h.el("#passkey-remove-confirm").hidden, true);

  const before = h.requests.filter(
    (request) => request.message.type === "passkey-remove",
  ).length;
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  assert.equal(
    h.requests.filter((request) => request.message.type === "passkey-remove").length,
    before,
    "uncertain state must suppress repeated removal RPCs",
  );

  h.el("#detail-back").listeners.get("click")();
  await settle();
  h.el("#vault-list").children[0].listeners.get("click")();
  const fresh = h.take("item-get");
  fresh.resolve({
    detail: passkeyDetail(),
    connected: true,
    passkeyManagementSupported: true,
  });
  await settle();
  assert.equal(
    h.el("#passkey-remove").hidden,
    false,
    "a fresh item-get with passkey metadata recovers the control",
  );
});

test("capability state refresh hides a now-unsupported passkey delete button", async () => {
  const h = harness();
  await openDetail(h, passkeyDetail(), {
    state: { passkeyManagementSupported: true },
    reply: { passkeyManagementSupported: true },
  });
  assert.equal(h.el("#passkey-remove").hidden, false);
  h.poll();
  const state = h.take("state");
  state.resolve({
    connected: true,
    status: "ready",
    origin: "https://example.test/",
    candidates: [],
    vaultItems: [],
    passkeyManagementSupported: false,
  });
  await settle();
  assert.equal(h.el("#passkey-remove").hidden, true);
  assert.match(h.el("#passkey-detail-unsupported").textContent, /升级原生宿主/);
});

const MCRED1 = core.base64URLEncode(new Uint8Array(32).fill(5));
const MCRED2 = core.base64URLEncode(new Uint8Array(32).fill(6));
const MREV1 = "1".repeat(64);
const MREV2 = "2".repeat(64);
const MREV3 = "3".repeat(64);

function passkeyEntry(credentialId, revision, userName, displayName) {
  return {
    credential_id: credentialId,
    credential_revision: revision,
    rp_id: "example.test",
    user_name: userName,
    display_name: displayName,
  };
}
function multiPasskeyDetail(entries, overrides = {}) {
  return {
    ...detailDocument(),
    has_passkey: entries.length > 0,
    passkey_count: entries.length,
    passkeys: entries,
    ...overrides,
  };
}
function twoPasskeys() {
  return [
    passkeyEntry(MCRED1, MREV1, "ada@example.test", "Ada Lovelace"),
    passkeyEntry(MCRED2, MREV2, "grace@example.test", "Grace Hopper"),
  ];
}

async function openMultiPasskeyDetail(h, detail) {
  await openDetail(h, detail, {
    state: { passkeyManagementSupported: true },
    reply: { passkeyManagementSupported: true },
  });
}

async function resolveRemovalRefresh(h, captured, refreshedDetail) {
  await settle();
  const list = h.take("vault-search");
  list.resolve({
    connected: true,
    passkeyManagementSupported: true,
    vaultItems: [{
      id: ID, revision: captured.revision, category: "login", title: "Login",
      urls: ["https://example.test/"], tags: [], favorite: false,
    }],
  });
  await settle();
  const refreshed = h.take("item-get");
  assert.equal(refreshed.message.revision, captured.revision);
  refreshed.resolve({
    connected: true,
    passkeyManagementSupported: true,
    detail: refreshedDetail,
  });
  await settle();
}

test("multi passkey detail requires an explicit choice and deletes the exact SECOND child", async () => {
  const h = harness();
  await openMultiPasskeyDetail(h, multiPasskeyDetail(twoPasskeys()));
  assert.equal(h.el("#passkey-detail").hidden, false);
  assert.equal(h.el("#passkey-select-row").hidden, false);
  assert.equal(h.el("#passkey-select").children.length, 3, "placeholder plus two entries");
  assert.equal(h.el("#passkey-select").value, "", "no automatic first selection");
  assert.equal(h.el("#passkey-rp").textContent, "-");
  assert.equal(h.el("#passkey-remove").hidden, true, "choice is required before removal");

  h.el("#passkey-select").value = MCRED2;
  h.el("#passkey-select").listeners.get("change")({ target: { value: MCRED2 } });
  assert.equal(h.el("#passkey-username").textContent, "grace@example.test");
  assert.match(h.el("#passkey-credential-hint").textContent, /^.{6}….{6}$/);
  assert.equal(h.el("#passkey-remove").hidden, false);
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  const remove = h.take("passkey-remove");
  assert.deepEqual(Object.keys(remove.message).sort(), [
    "credential_id", "credential_revision", "id", "revision", "type",
  ]);
  assert.equal(remove.message.id, ID);
  assert.equal(remove.message.revision, REV);
  assert.equal(remove.message.credential_id, MCRED2);
  assert.equal(remove.message.credential_revision, MREV2);
  remove.resolve({
    connected: true,
    passkeyManagementSupported: true,
    passkeyRemoved: { item_id: ID, revision: NEXT, credential_id: MCRED2 },
  });
  await resolveRemovalRefresh(
    h,
    { revision: NEXT },
    multiPasskeyDetail([twoPasskeys()[0]], { revision: NEXT }),
  );
  assert.equal(h.el("#passkey-detail").hidden, false, "sibling credential remains");
  assert.equal(h.el("#passkey-username").textContent, "ada@example.test");
  assert.equal(h.el("#passkey-select-row").hidden, true, "single sibling keeps direct delete");
  assert.equal(h.el("#passkey-remove").hidden, false);
  assert.match(h.el("#passkey-status").textContent, /其他 Passkey/);
  assert.match(shown(h), /ada/, "login fields remain");
  assert.equal(
    h.el("#vault-list").children[0].dataset.itemRevision,
    NEXT,
    "list row adopts the fresh parent revision",
  );
});

test("changing the passkey choice clears confirmation without sending a removal", async () => {
  const h = harness();
  await openMultiPasskeyDetail(h, multiPasskeyDetail(twoPasskeys()));
  h.el("#passkey-select").value = MCRED1;
  h.el("#passkey-select").listeners.get("change")({ target: { value: MCRED1 } });
  h.el("#passkey-remove").listeners.get("click")();
  assert.equal(h.el("#passkey-remove-confirm").hidden, false);
  h.el("#passkey-select").value = MCRED2;
  h.el("#passkey-select").listeners.get("change")({ target: { value: MCRED2 } });
  assert.equal(h.el("#passkey-remove-confirm").hidden, true);
  assert.equal(h.el("#passkey-remove-cancel").hidden, true);
  assert.equal(h.el("#passkey-remove-warning").hidden, true);
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  assert.equal(
    h.requests.some((request) => request.message.type === "passkey-remove"),
    false,
    "a cleared confirmation must not send an RPC",
  );
  assert.equal(h.el("#passkey-username").textContent, "grace@example.test");
});

test("a refreshed parent or child revision resets the multi selection and confirmation", async () => {
  const h = harness();
  await openMultiPasskeyDetail(h, multiPasskeyDetail(twoPasskeys()));
  h.el("#passkey-select").value = MCRED1;
  h.el("#passkey-select").listeners.get("change")({ target: { value: MCRED1 } });
  h.el("#passkey-remove").listeners.get("click")();
  assert.equal(h.el("#passkey-remove-confirm").hidden, false);

  h.el("#detail-back").listeners.get("click")();
  await settle();
  h.el("#vault-list").children[0].listeners.get("click")();
  const fresh = h.take("item-get");
  fresh.resolve({
    connected: true,
    passkeyManagementSupported: true,
    detail: multiPasskeyDetail(
      [
        passkeyEntry(MCRED1, MREV3, "ada@example.test", "Ada Lovelace"),
        passkeyEntry(MCRED2, MREV2, "grace@example.test", "Grace Hopper"),
      ],
      { revision: REV },
    ),
  });
  await settle();
  assert.equal(h.el("#passkey-select").value, "", "child revision change clears the choice");
  assert.equal(h.el("#passkey-remove").hidden, true);
  assert.equal(h.el("#passkey-remove-confirm").hidden, true);

  h.el("#detail-back").listeners.get("click")();
  await settle();
  h.el("#vault-list").children[0].listeners.get("click")();
  const parentFresh = h.take("item-get");
  parentFresh.resolve({
    connected: true,
    passkeyManagementSupported: true,
    detail: multiPasskeyDetail(twoPasskeys(), { revision: NEXT }),
  });
  await settle();
  assert.equal(h.el("#passkey-select").value, "", "parent revision change clears the choice");
  assert.equal(h.el("#passkey-remove").hidden, true);
});

test("removing the last sibling clears passkey metadata but keeps the login", async () => {
  const h = harness();
  const detail = multiPasskeyDetail(twoPasskeys());
  await openMultiPasskeyDetail(h, detail);
  h.el("#passkey-select").value = MCRED1;
  h.el("#passkey-select").listeners.get("change")({ target: { value: MCRED1 } });
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  const first = h.take("passkey-remove");
  first.resolve({
    connected: true,
    passkeyManagementSupported: true,
    passkeyRemoved: { item_id: ID, revision: NEXT, credential_id: MCRED1 },
  });
  await resolveRemovalRefresh(
    h,
    { revision: NEXT },
    multiPasskeyDetail([twoPasskeys()[1]], { revision: NEXT }),
  );
  assert.match(h.el("#passkey-status").textContent, /其他 Passkey/);
  assert.equal(h.el("#passkey-username").textContent, "grace@example.test");

  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  const second = h.take("passkey-remove");
  assert.equal(second.message.credential_id, MCRED2);
  assert.equal(second.message.credential_revision, MREV2);
  second.resolve({
    connected: true,
    passkeyManagementSupported: true,
    passkeyRemoved: { item_id: ID, revision: "a".repeat(64), credential_id: MCRED2 },
  });
  await resolveRemovalRefresh(
    h,
    { revision: "a".repeat(64) },
    { ...detailDocument(), revision: "a".repeat(64), has_passkey: false },
  );
  assert.equal(h.el("#passkey-detail").hidden, true);
  assert.match(h.el("#passkey-status").textContent, /此登录和其他信息仍保留/);
  assert.match(shown(h), /ada/, "login fields remain after the last passkey");
  assert.equal(
    h.requests.some((request) => request.message.type === "passkey-remove"),
    true,
  );
});

test("a malformed or oversized passkey array fails closed without singleton fallback", async () => {
  const legacy = passkeyEntry(MCRED1, MREV1, "ada@example.test", "Ada Lovelace");
  delete legacy.credential_revision;
  const cases = [
    [legacy],
    [twoPasskeys()[0], { ...twoPasskeys()[0], credential_revision: MREV3 }],
    Array.from({ length: 17 }, (_, index) =>
      passkeyEntry(
        core.base64URLEncode(new Uint8Array(32).fill(index)),
        index.toString(16).padStart(2, "0").repeat(32),
        "user" + index,
        "User " + index,
      ),
    ),
  ];
  for (const passkeys of cases) {
    const h = harness();
    await openMultiPasskeyDetail(h, {
      ...detailDocument(),
      has_passkey: true,
      passkey_count: passkeys.length,
      passkeys,
      passkey: passkeyEntry(MCRED1, MREV1, "legacy@example.test", "Legacy"),
    });
    assert.equal(h.el("#passkey-detail").hidden, false);
    assert.equal(h.el("#passkey-select-row").hidden, true);
    assert.equal(h.el("#passkey-username").textContent, "-", "no legacy fallback");
    assert.equal(h.el("#passkey-remove").hidden, true);
    assert.match(h.el("#passkey-detail-unsupported").textContent, /未提供可安全显示/);
  }
});

test("unknown multi removal blocks retry until a different choice is made", async () => {
  const h = harness();
  await openMultiPasskeyDetail(h, multiPasskeyDetail(twoPasskeys()));
  h.el("#passkey-select").value = MCRED1;
  h.el("#passkey-select").listeners.get("change")({ target: { value: MCRED1 } });
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  h.take("passkey-remove").resolve({
    connected: true,
    passkeyManagementSupported: true,
    passkeyRemoveError: "uncertain",
  });
  await settle();
  assert.match(h.el("#passkey-status").textContent, /结果未确认/);
  assert.equal(h.el("#passkey-remove").hidden, true);
  const before = h.requests.filter(
    (request) => request.message.type === "passkey-remove",
  ).length;
  h.el("#passkey-remove").listeners.get("click")();
  h.el("#passkey-remove-confirm").listeners.get("click")();
  await settle();
  assert.equal(
    h.requests.filter((request) => request.message.type === "passkey-remove").length,
    before,
    "uncertain state must block a retry for the same child selector",
  );

  h.el("#passkey-select").value = MCRED2;
  h.el("#passkey-select").listeners.get("change")({ target: { value: MCRED2 } });
  assert.equal(h.el("#passkey-remove").hidden, false, "a different choice starts fresh");
  assert.equal(h.el("#passkey-status").textContent, "");
});

test("list rows expose multi-passkey count without a detail array", async () => {
  const h = harness();
  h.take("state").resolve({
    connected: true,
    status: "ready",
    origin: "https://example.test/",
    candidates: [],
    passkeyManagementSupported: true,
    vaultItems: [{
      id: ID, revision: REV, category: "login", title: "Login",
      urls: ["https://example.test/"], tags: [], favorite: false,
      has_passkey: true, passkey_count: 2,
    }],
    generatorDefaults: { mode: "random", length: 24 },
  });
  await settle();
  const row = h.el("#vault-list").children[0];
  const subtitle = row.children.find((child) => child.className === "vault-item-subtitle");
  const badge = row.children.find((child) => child.className === "badge");
  assert.equal(subtitle.textContent, "2 个 Passkey");
  assert.equal(badge.textContent, "Passkey ×2 · 登录");
});
