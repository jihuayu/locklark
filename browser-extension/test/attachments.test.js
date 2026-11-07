const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

const tick = () => new Promise((resolve) => setImmediate(resolve));
const ITEM = "b".repeat(32);
const REV = "c".repeat(64);
const TRANSFER = "d".repeat(32);
const ATTACHMENT = "e".repeat(32);
const META = {
  id: ATTACHMENT,
  file_name: "diagram.png",
  size: 0,
  mime_type: "image/png",
  sha256: "f".repeat(64),
};

function harness(options = {}) {
  const listeners = [];
  const sent = [];
  let portMessage;
  const capabilities = Array.isArray(options.capabilities)
    ? [...options.capabilities]
    : [];
  const port = {
    onMessage: { addListener: (fn) => (portMessage = fn) },
    onDisconnect: { addListener: () => {} },
    disconnect: () => {},
    postMessage: (request) => {
      sent.push(request);
      if (request.type === "hello")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "paired",
            capability: "a".repeat(32),
            capabilities,
          }),
        );
      if (typeof options.onRequest === "function") {
        const reply = options.onRequest(request);
        if (reply) queueMicrotask(() => portMessage(reply));
      }
    },
  };
  const api = {
    storage: { local: { get: async () => ({}), set: async () => {} } },
    runtime: {
      id: "fixed",
      getURL: (name) => "chrome-extension://fixed/" + name,
      connectNative: () => port,
      onMessage: { addListener: (fn) => listeners.push(fn) },
      onInstalled: { addListener: () => {} },
      lastError: undefined,
    },
    tabs: {
      query: async () => [{ id: 1, url: "https://example.test/", windowId: 1 }],
      onActivated: { addListener: () => {} },
      onUpdated: { addListener: () => {} },
      onRemoved: { addListener: () => {} },
    },
    windows: { WINDOW_ID_NONE: -1, onFocusChanged: { addListener: () => {} } },
    action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {}, setTitle: () => {} },
    contextMenus: { create: () => {}, removeAll: () => {}, onClicked: { addListener: () => {} } },
    commands: { onCommand: { addListener: () => {} } },
    scripting: { executeScript: async () => [] },
  };
  const context = {
    chrome: api,
    LocklarkCore: core,
    crypto: webcrypto,
    setTimeout,
    clearTimeout,
    console: {},
    importScripts: () => {},
    URL,
    Uint8Array,
    TextEncoder,
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../background.js"), "utf8"),
    context,
  );
  const sender = { id: "fixed", url: "chrome-extension://fixed/popup.html" };
  return {
    sent,
    deliver: (reply) => portMessage(reply),
    send: (message, from = sender) =>
      new Promise((resolve) => {
        let handled = false;
        for (const listener of listeners)
          if (listener(message, from, resolve) === true) handled = true;
        if (!handled) resolve(undefined);
      }),
    async connect() {
      await this.send({ type: "connect" });
      await tick();
    },
  };
}

function attachmentHost() {
  const seen = [];
  const state = { offset: 0, size: 0 };
  return {
    seen,
    state,
    onRequest: (request) => {
      if (request.type === "attachment-begin") {
        seen.push(request);
        return {
          v: 1,
          id: request.id,
          type: "attachment-transfer",
          transfer_id: TRANSFER,
          offset: 0,
          size: request.size,
          expires_in_seconds: 120,
        };
      }
      if (request.type === "attachment-chunk") {
        seen.push(request);
        const bytes = core.base64Decode(request.data, 65536);
        state.offset = request.offset + bytes.length;
        return {
          v: 1,
          id: request.id,
          type: "attachment-transfer",
          transfer_id: TRANSFER,
          offset: state.offset,
          size: state.size,
          expires_in_seconds: 120,
        };
      }
      if (request.type === "attachment-cancel") {
        seen.push(request);
        return {
          v: 1,
          id: request.id,
          type: "attachment-cancelled",
          transfer_id: request.transfer_id,
        };
      }
      if (request.type === "attachment-commit") {
        seen.push(request);
        return {
          v: 1,
          id: request.id,
          type: "attachment-saved",
          item_id: ITEM,
          revision: "1".repeat(64),
          attachment: { ...META, size: state.size },
        };
      }
      return null;
    },
  };
}

test("core validates strict attachment wire shapes and rejects malformed ones", () => {
  const transfer = {
    v: 1,
    id: "a".repeat(32),
    type: "attachment-transfer",
    transfer_id: TRANSFER,
    offset: 0,
    size: 0,
    expires_in_seconds: 120,
  };
  assert.equal(core.validResponse(transfer), true);
  for (const broken of [
    { ...transfer, transfer_id: "zz" },
    { ...transfer, offset: 1, size: 0 },
    { ...transfer, size: 2097153, offset: 0 },
    { ...transfer, expires_in_seconds: 0 },
    { ...transfer, extra: 1 },
    { ...transfer, id: "a".repeat(32) + "x" },
  ])
    assert.equal(core.validResponse(broken), false, JSON.stringify(broken));

  const data = {
    v: 1,
    id: "a".repeat(32),
    type: "attachment-data",
    item_id: ITEM,
    revision: REV,
    attachment: META,
    offset: 0,
    next_offset: 0,
    done: true,
    data: "",
  };
  assert.equal(core.validResponse(data), true, "zero-length read is valid");
  assert.equal(
    core.validResponse({ ...data, done: false }),
    false,
    "zero file must finish on the first read",
  );
  assert.equal(core.validResponse({ ...data, next_offset: 3, data: "AAAA" }), false);
  assert.equal(core.validResponse({ ...data, data: "AAA" }), false, "strict base64");
  assert.equal(
    core.validResponse({ ...data, data: "AAAA", next_offset: 3, done: true }),
    false,
    "offset mismatch",
  );

  const saved = {
    v: 1,
    id: "a".repeat(32),
    type: "attachment-saved",
    item_id: ITEM,
    revision: REV,
    attachment: META,
  };
  assert.equal(core.validResponse(saved), true);
  assert.equal(core.validResponse({ ...saved, attachment: { ...META, sha256: "F".repeat(64) } }), false);
  assert.equal(core.validResponse({ ...saved, attachment: { ...META, file_name: "../x" } }), false);
  assert.equal(core.validResponse({ ...saved, attachment: { ...META, size: 2097153 } }), false);
  assert.equal(core.validResponse({ ...saved, attachment: { ...META, data: "AAAA" } }), false);
  assert.equal(
    core.validResponse({ v: 1, id: "a".repeat(32), type: "attachment-removed", item_id: ITEM, revision: REV, attachment_id: ATTACHMENT }),
    true,
  );
  assert.equal(
    core.validResponse({ v: 1, id: "a".repeat(32), type: "attachment-cancelled", transfer_id: TRANSFER }),
    true,
  );
  const detail = {
    v: 1,
    id: "a".repeat(32),
    type: "item-detail",
    item: { id: ITEM, revision: REV, title: "T", category: "login", attachments: [META] },
  };
  assert.equal(core.validResponse(detail), true, "metadata-only attachments in detail");
  assert.equal(
    core.validResponse({ ...detail, item: { ...detail.item, attachments: [{ ...META, data: "AA==" }] } }),
    false,
  );
});

test("core base64 helpers round-trip chunks and enforce bounds", () => {
  const bytes = new Uint8Array(65536);
  for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 37) & 0xff;
  const encoded = core.base64Encode(bytes);
  const decoded = core.base64Decode(encoded, 65536);
  assert.equal(decoded.length, bytes.length);
  assert.deepEqual(Buffer.from(decoded).toString("hex"), Buffer.from(bytes).toString("hex"));
  assert.equal(core.base64Encode(new Uint8Array(0)), "");
  assert.deepEqual(Array.from(core.base64Decode("")), []);
  const tooBig = new Uint8Array(65537);
  assert.equal(core.base64Decode(core.base64Encode(tooBig), 65536), null);
  assert.equal(core.base64Decode("AA=A", 65536), null);
  assert.equal(core.safeFileName("../../etc/passwd"), "");
  assert.equal(core.safeFileName("notes.txt"), "notes.txt");
  assert.deepEqual(core.validClearFields(["notes", "section:s1:f1"]), ["notes", "section:s1:f1"]);
  assert.equal(core.validClearFields(["notes", "notes"]), null, "duplicates rejected");
  assert.equal(core.validClearFields(["password"]), null, "unknown stable key rejected");
});

test("background forwards begin/chunk/commit with exact wire keys and no state bytes", async () => {
  const host = attachmentHost();
  const h = harness({ capabilities: ["attachments-v1"], onRequest: host.onRequest });
  await h.connect();
  const payload = new Uint8Array(70000);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 11) & 0xff;
  const sha256 = require("node:crypto").createHash("sha256").update(payload).digest("hex");
  host.state.offset = 0;
  host.state.size = payload.length;
  const begin = await h.send({
    type: "attachment-begin",
    id: ITEM,
    revision: REV,
    file_name: "diagram.png",
    size: payload.length,
    sha256,
    mime_type: "image/png",
  });
  assert.equal(begin.attachmentTransfer?.transfer_id, TRANSFER);
  assert.equal(begin.attachmentTransfer.offset, 0);
  const wireBegin = h.sent.find((r) => r.type === "attachment-begin");
  assert.deepEqual(Object.keys(wireBegin).sort(), [
    "capability", "file_name", "id", "item_id", "mime_type", "revision", "sha256", "size", "type", "v",
  ]);
  assert.equal(wireBegin.capability, "a".repeat(32));

  let offset = 0;
  while (offset < payload.length) {
    const chunk = payload.subarray(offset, Math.min(offset + 65536, payload.length));
    const advanced = await h.send({
      type: "attachment-chunk",
      transfer_id: begin.attachmentTransfer.transfer_id,
      offset,
      data: core.base64Encode(chunk),
    });
    assert.equal(advanced.attachmentTransfer.offset, offset + chunk.length);
    offset = advanced.attachmentTransfer.offset;
  }
  const chunks = h.sent.filter((r) => r.type === "attachment-chunk");
  assert.equal(chunks.length, 2, "2 MiB protocol chunks a >64 KiB file");
  assert.deepEqual(Object.keys(chunks[0]).sort(), [
    "capability", "data", "id", "offset", "transfer_id", "type", "v",
  ]);
  assert.deepEqual(Array.from(core.base64Decode(chunks[1].data, 65536)), Array.from(payload.subarray(65536)));

  const committed = await h.send({ type: "attachment-commit", transfer_id: TRANSFER });
  assert.equal(committed.attachmentSaved.revision, "1".repeat(64));
  assert.equal(committed.attachmentSaved.attachment.id, ATTACHMENT);
  assert.equal(committed.attachmentSaved.attachment.size, payload.length);
  const state = await h.send({ type: "state" });
  assert.equal(state.attachmentsSupported, true);
  const json = JSON.stringify(state);
  assert.equal(json.includes(core.base64Encode(payload.subarray(0, 512))), false);
  assert.equal(json.includes(chunks[0].data.slice(0, 128)), false);
  assert.equal(json.includes("/9j/"), false);
  await h.send({ type: "disconnect" });
});

test("background rejects malformed lengths, tokens and mismatched offsets", async () => {
  const host = attachmentHost();
  const h = harness({ capabilities: ["attachments-v1"], onRequest: host.onRequest });
  await h.connect();
  const before = h.sent.length;
  const refused = async (message) => {
    const reply = await h.send(message);
    assert.equal(reply?.error, "refused", JSON.stringify(message).slice(0, 120));
  };
  await refused({
    type: "attachment-begin", id: ITEM, revision: REV, file_name: "../x", size: 4, sha256: "a".repeat(64),
  });
  await refused({
    type: "attachment-begin", id: ITEM, revision: REV, file_name: "x.bin", size: 2097153, sha256: "a".repeat(64),
  });
  await refused({
    type: "attachment-begin", id: ITEM, revision: REV, file_name: "x.bin", size: 4, sha256: "A".repeat(64),
  });
  assert.equal(h.sent.length, before, "invalid requests never reach the host");

  host.state.offset = 0;
  host.state.size = 8;
  const begin = await h.send({
    type: "attachment-begin", id: ITEM, revision: REV, file_name: "x.bin", size: 8, sha256: "a".repeat(64),
  });
  assert.ok(begin.attachmentTransfer);
  await refused({ type: "attachment-begin", id: ITEM, revision: REV, file_name: "y.bin", size: 1, sha256: "a".repeat(64) });
  await refused({ type: "attachment-chunk", transfer_id: "9".repeat(32), offset: 0, data: "AAAA" });
  await refused({ type: "attachment-chunk", transfer_id: TRANSFER, offset: 2, data: "AAAA" });
  await refused({ type: "attachment-chunk", transfer_id: TRANSFER, offset: 0, data: "" });
  await refused({ type: "attachment-chunk", transfer_id: TRANSFER, offset: 0, data: core.base64Encode(new Uint8Array(65537)) });
  await refused({ type: "attachment-commit", transfer_id: TRANSFER });
  await h.send({ type: "attachment-cancel", transfer_id: TRANSFER });
  await h.send({ type: "disconnect" });
});

test("late attachment responses after lock never resolve or display", async () => {
  let release = null;
  const h = harness({
    capabilities: ["attachments-v1"],
    onRequest: (request) => {
      if (request.type === "attachment-begin") return null;
      return null;
    },
  });
  await h.connect();
  const pending = h.send({
    type: "attachment-begin", id: ITEM, revision: REV, file_name: "x.bin", size: 1, sha256: "a".repeat(64),
  });
  await tick();
  const begin = h.sent.find((r) => r.type === "attachment-begin");
  assert.ok(begin);
  // Disconnect rejects every in-flight native call, so a late host frame is
  // never delivered to the popup.
  await h.send({ type: "disconnect" });
  const reply = await pending;
  assert.equal(reply?.attachmentTransfer, undefined);
  assert.equal(reply?.error, "refused");
  if (release) release();
});

test("old hosts without attachments-v1 report unsupported and stay untouched", async () => {
  const host = attachmentHost();
  const h = harness({ capabilities: ["stage-save-v1"], onRequest: host.onRequest });
  await h.connect();
  const before = h.sent.length;
  const reply = await h.send({
    type: "attachment-begin", id: ITEM, revision: REV, file_name: "x.bin", size: 1, sha256: "a".repeat(64),
  });
  assert.equal(reply.error, "refused");
  assert.match(reply.status, /不支持附件/);
  assert.equal(reply.attachmentsSupported, false);
  assert.equal(h.sent.length, before, "no native request without the capability");
  const state = await h.send({ type: "state" });
  assert.equal(state.attachmentsSupported, false);
  await h.send({ type: "disconnect" });
});

test("attachment read/remove validate offsets and return bytes only to the caller", async () => {
  const body = new Uint8Array([1, 2, 3, 4, 5]);
  const meta = {
    id: ATTACHMENT,
    file_name: "x.bin",
    size: body.length,
    sha256: require("node:crypto").createHash("sha256").update(body).digest("hex"),
  };
  const h = harness({
    capabilities: ["attachments-v1"],
    onRequest: (request) => {
      if (request.type === "attachment-read") {
        if (request.offset !== 0 || request.length !== 9) return null;
        return {
          v: 1, id: request.id, type: "attachment-data", item_id: ITEM, revision: REV,
          attachment: meta, offset: 0, next_offset: body.length, done: true,
          data: core.base64Encode(body),
        };
      }
      if (request.type === "attachment-remove")
        return { v: 1, id: request.id, type: "attachment-removed", item_id: ITEM, revision: "2".repeat(64), attachment_id: ATTACHMENT };
      return null;
    },
  });
  await h.connect();
  const read = await h.send({
    type: "attachment-read", id: ITEM, revision: REV, attachment_id: ATTACHMENT, offset: 0, length: 9,
  });
  assert.deepEqual(Array.from(core.base64Decode(read.attachmentData.data, 65536)), [1, 2, 3, 4, 5]);
  assert.equal(read.attachmentData.done, true);
  const state = JSON.stringify(await h.send({ type: "state" }));
  assert.equal(state.includes(core.base64Encode(body)), false);
  const bad = await h.send({ type: "attachment-read", id: ITEM, revision: REV, attachment_id: ATTACHMENT, offset: 0, length: 0 });
  assert.equal(bad.error, "refused");
  const removed = await h.send({ type: "attachment-remove", id: ITEM, revision: REV, attachment_id: ATTACHMENT });
  assert.equal(removed.attachmentRemoved?.revision, "2".repeat(64));
  await h.send({ type: "disconnect" });
});

test("mutation omits untouched protected values and honours explicit clears", () => {
  const original = {
    has_notes: true,
    notes: "",
    sections: [
      {
        id: "sec1",
        title: "Recovery",
        fields: [
          { id: "f1", label: "Code", type: "concealed", concealed: true, has_value: true, value: "", purpose: "totp" },
          { id: "f2", label: "Visible", type: "text", value: "plain" },
        ],
      },
    ],
  };
  const base = {
    category: "login",
    title: "Example",
    notes: "",
    sections: [
      {
        id: "sec1",
        title: "Recovery",
        fields: [
          { id: "f1", label: "Code", type: "concealed", concealed: true, value: "" },
          { id: "f2", label: "Visible", type: "text", value: "plain" },
          { id: "f3", label: "New", type: "text", value: "added" },
        ],
      },
    ],
  };
  const cleared = core.itemToNativeMutation(
    { ...base, clear_fields: ["notes", "section:sec1:f1"] },
    { original },
  );
  assert.equal(cleared.notes, "");
  assert.deepEqual(
    cleared.clear_fields,
    ["notes", "section:sec1:f1"],
    "exact clear targets are forwarded to the host",
  );
  const fields = cleared.sections[0].fields;
  assert.equal(fields.find((f) => f.id === "f1").value, "", "explicit clear sends an empty value");
  assert.equal(fields.find((f) => f.id === "f1").concealed, true);
  assert.equal(fields.find((f) => f.id === "f1").purpose, "totp", "purpose preserved");
  assert.equal(fields.find((f) => f.id === "f2").value, "plain", "visible edit kept");
  assert.equal(fields.find((f) => f.id === "f3").value, "added", "added field kept");

  const untouched = core.itemToNativeMutation(
    { ...base, clear_fields: [] },
    { original },
  );
  assert.equal(Object.hasOwn(untouched.sections[0].fields.find((f) => f.id === "f1"), "value"), false);
  assert.equal(Object.hasOwn(untouched, "notes"), false, "blank notes stay omitted");
  assert.equal(Object.hasOwn(untouched, "clear_fields"), false, "empty clears stay omitted");

  const masked = core.itemToNativeMutation(
    {
      ...base,
      clear_fields: [],
      sections: [{ id: "sec1", title: "Recovery", fields: [{ id: "f1", label: "Code", type: "concealed", value: "••••••" }] }],
    },
    { original },
  );
  assert.equal(Object.hasOwn(masked.sections[0].fields[0], "value"), false, "bullets never become values");

  assert.deepEqual(
    core.itemToNativeMutation({ ...base, clear_fields: [], sections: [] }, { original }).sections,
    [],
    "empty sections deliberately remove all",
  );
  assert.equal(
    Object.hasOwn(core.itemToNativeMutation({ category: "login", title: "T", notes: "" }, { original }), "sections"),
    false,
    "omitted sections preserve all",
  );
  assert.equal(core.itemToNativeMutation({ ...base, clear_fields: ["notes", "notes"] }, { original }), null);
  assert.equal(core.itemToNativeMutation({ ...base, clear_fields: ["password"] }, { original }), null);
  assert.equal(core.itemToNativeMutation({ ...base, clear_fields: ["notes"], notes: "new text" }, { original }), null);
  assert.equal(
    core.itemToNativeMutation({ ...base, clear_fields: ["notes"], notes: "   " }, { original }),
    null,
    "whitespace counts as a conflicting value like the host",
  );
  assert.equal(
    core.itemToNativeMutation(
      { category: "note", title: "N", content: "x", clear_fields: ["notes"] },
      { original },
    ),
    null,
    "secure-note content conflicts with a notes clear",
  );
  const removed = core.itemToNativeMutation(
    { ...base, clear_fields: [], sections: [{ id: "sec1", title: "Recovery", fields: [{ id: "f1", label: "Code", type: "concealed", value: "" }] }] },
    { original },
  );
  assert.deepEqual(removed.sections[0].fields.map((f) => f.id), ["f1"], "removed rows drop from supplied sections");
  const flatDuplicate = core.itemToNativeMutation(
    {
      category: "login",
      title: "Example",
      notes: "",
      sections: [{ id: "sec1", title: "Recovery", fields: [{ id: "f1", label: "Code", type: "concealed", value: "" }] }],
      fields: [{ id: "f1", label: "Code", type: "concealed", value: "" }],
    },
    { original },
  );
  assert.equal(flatDuplicate.sections.length, 1, "flat fields merge into the stable section");
  assert.equal(flatDuplicate.sections[0].id, "sec1");
  assert.equal(
    Object.hasOwn(flatDuplicate.sections[0].fields.find((f) => f.id === "f1"), "value"),
    false,
    "merged masked field still omits its value",
  );
  assert.equal(core.validItemForSave({ ...base, clear_fields: ["notes"] }), true);
  assert.equal(core.validItemForSave({ ...base, clear_fields: ["bogus"] }), false);
});

test("cancel during an in-flight chunk cannot resurrect or clear transfers", async () => {
  const h = harness({
    capabilities: ["attachments-v1"],
    onRequest: () => null,
  });
  await h.connect();
  const lastSent = (type) => h.sent.filter((request) => request.type === type).at(-1);
  const begin = (name) =>
    h.send({
      type: "attachment-begin",
      id: ITEM,
      revision: REV,
      file_name: name,
      size: 4,
      sha256: "a".repeat(64),
    });

  const first = begin("a.bin");
  await tick();
  const firstBegin = lastSent("attachment-begin");
  h.deliver({
    v: 1, id: firstBegin.id, type: "attachment-transfer",
    transfer_id: "1".repeat(32), offset: 0, size: 4, expires_in_seconds: 120,
  });
  assert.equal((await first).attachmentTransfer.transfer_id, "1".repeat(32));

  const chunk = h.send({
    type: "attachment-chunk",
    transfer_id: "1".repeat(32),
    offset: 0,
    data: core.base64Encode(new Uint8Array([1, 2, 3, 4])),
  });
  await tick();
  const heldChunk = lastSent("attachment-chunk");
  const cancel = h.send({ type: "attachment-cancel", transfer_id: "1".repeat(32) });
  await tick();
  const heldCancel = lastSent("attachment-cancel");

  // The chunk reply arrives after the cancel: it must be refused and must not
  // reinstall the cancelled transfer metadata.
  h.deliver({
    v: 1, id: heldChunk.id, type: "attachment-transfer",
    transfer_id: "1".repeat(32), offset: 4, size: 4, expires_in_seconds: 120,
  });
  assert.equal((await chunk).error, "refused");

  // A new upload is therefore allowed, and the late old cancel reply cannot
  // clear its record.
  const second = begin("b.bin");
  await tick();
  const secondBegin = lastSent("attachment-begin");
  assert.notEqual(secondBegin.id, firstBegin.id, "new begin reaches the host");
  h.deliver({
    v: 1, id: secondBegin.id, type: "attachment-transfer",
    transfer_id: "2".repeat(32), offset: 0, size: 4, expires_in_seconds: 120,
  });
  assert.equal((await second).attachmentTransfer.transfer_id, "2".repeat(32));
  h.deliver({
    v: 1, id: heldCancel.id, type: "attachment-cancelled",
    transfer_id: "1".repeat(32),
  });
  assert.equal((await cancel).attachmentCancelled.transfer_id, "1".repeat(32));

  const nextChunk = h.send({
    type: "attachment-chunk",
    transfer_id: "2".repeat(32),
    offset: 0,
    data: core.base64Encode(new Uint8Array([1, 2, 3, 4])),
  });
  await tick();
  const newChunk = lastSent("attachment-chunk");
  assert.notEqual(newChunk.id, heldChunk.id, "new chunk is forwarded");
  h.deliver({
    v: 1, id: newChunk.id, type: "attachment-transfer",
    transfer_id: "2".repeat(32), offset: 4, size: 4, expires_in_seconds: 120,
  });
  assert.equal((await nextChunk).attachmentTransfer.offset, 4);
  await h.send({ type: "disconnect" });
});

test("expired upload metadata is pruned so a new begin is not blocked", async () => {
  const h = harness({
    capabilities: ["attachments-v1"],
    onRequest: (request) => {
      if (request.type !== "attachment-begin") return null;
      return {
        v: 1,
        id: request.id,
        type: "attachment-transfer",
        transfer_id: "3".repeat(32),
        offset: 0,
        size: 1,
        expires_in_seconds: 1,
      };
    },
  });
  await h.connect();
  const begin = () =>
    h.send({
      type: "attachment-begin",
      id: ITEM,
      revision: REV,
      file_name: "a.bin",
      size: 1,
      sha256: "a".repeat(64),
    });
  assert.ok((await begin()).attachmentTransfer);
  assert.equal((await begin()).error, "refused", "active transfer blocks a second begin");
  await new Promise((resolve) => setTimeout(resolve, 1200));
  const after = await begin();
  assert.ok(after.attachmentTransfer, "expired orphan metadata no longer blocks uploads");
  await h.send({ type: "disconnect" });
});
