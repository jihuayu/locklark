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
  let pagehide = null;
  const document = {
    body: { dataset: { vault: "1" } },
    visibilityState: "visible",
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector);
    },
    querySelectorAll() {
      return [];
    },
    createElement: element,
    createTextNode: (text) => ({ textContent: text }),
    addEventListener() {},
  };
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
    setInterval: () => 0,
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

async function openDetail(h, detail) {
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
  });
  await settle();
  h.el("#vault-list").children[0].listeners.get("click")();
  h.take("item-get").resolve({ detail, connected: true });
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
