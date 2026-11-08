const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const core = require("../core.js");

const POPUP = path.join(__dirname, "../popup.js");

function element() {
  return {
    textContent: "",
    disabled: false,
    hidden: false,
    checked: false,
    className: "",
    type: "",
    dataset: {},
    style: {},
    attributes: {},
    children: [],
    listeners: new Map(),
    isConnected: true,
    addEventListener(type, callback) {
      this.listeners.set(type, callback);
    },
    replaceChildren(...children) {
      this.children = children;
    },
    append(...children) {
      this.children.push(...children);
    },
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

function harness() {
  const elements = new Map();
  const requests = [];
  const clipboardWrites = [];
  const timers = new Map();
  const windowListeners = new Map();
  let nextTimer = 1;
  const body = element();
  body.dataset.vault = "1";
  body.dataset.view = "vault";
  const document = {
    body,
    visibilityState: "visible",
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector);
    },
    querySelectorAll() {
      return [];
    },
    createElement() {
      return element();
    },
    createTextNode(text) {
      return { textContent: text };
    },
    addEventListener() {},
  };
  const state = () => ({
    connected: true,
    candidates: [],
    vaultItems: [],
    origin: "https://example.test",
    clipboardClearSeconds: 30,
    generatedHistory: [],
  });
  const context = {
    LocklarkCore: core,
    document,
    navigator: {
      clipboard: {
        writeText(value) {
          clipboardWrites.push(value);
          context.navigator.clipboard.value = value;
          return Promise.resolve();
        },
        value: "",
      },
    },
    chrome: {
      runtime: {
        sendMessage(message) {
          return new Promise((resolve) => {
            requests.push({ message, resolve });
            setImmediate(() => {
              if (message.type === "generate")
                resolve({
                  password: "Private-Canary-1",
                  profile: { mode: "random", entropy_bits_floor: 77 },
                });
              else resolve(state());
            });
          });
        },
      },
    },
    URL,
    Blob,
    Uint8Array,
    crypto: require("node:crypto").webcrypto,
    setTimeout(callback) {
      const id = nextTimer++;
      timers.set(id, callback);
      return id;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
    setInterval() {
      return 1;
    },
    clearInterval() {},
    addEventListener(type, callback) {
      windowListeners.set(type, callback);
    },
  };
  context.globalThis = context;
  vm.runInNewContext(fs.readFileSync(POPUP, "utf8"), context);
  return {
    elements,
    requests,
    clipboardWrites,
    windowListeners,
    context,
    el(selector) {
      return elements.get(selector);
    },
    async flush() {
      for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r));
    },
    runTimers() {
      while (timers.size) {
        const [id, callback] = timers.entries().next().value;
        timers.delete(id);
        callback();
      }
    },
    async generate() {
      this.el("#gen-regenerate").listeners.get("click")();
      await this.flush();
    },
  };
}

test("browser copy never schedules a blank write or overwrites a later foreign owner", async () => {
  const h = harness();
  await h.flush();
  await h.generate();
  assert.equal(h.el("#gen-preview").textContent, "Private-Canary-1");
  assert.equal(h.el("#gen-copy").disabled, false);

  h.el("#gen-copy").listeners.get("click")();
  await h.flush();
  assert.deepEqual(h.clipboardWrites, ["Private-Canary-1"]);
  assert.match(
    h.el("#gen-status").textContent,
    /已复制；浏览器无法保证自动清除，请按需手动清理/,
  );

  // A later owner replaces the clipboard. Any old automatic-clear timer would
  // now blank or overwrite that foreign value when it fires.
  h.context.navigator.clipboard.value = "FOREIGN-OWNER";
  const before = h.clipboardWrites.slice();
  h.runTimers();
  await h.flush();
  assert.deepEqual(h.clipboardWrites, before, "timers wrote to the clipboard");
  assert.equal(h.context.navigator.clipboard.value, "FOREIGN-OWNER");
});

test("pagehide and lock never turn the removed timer into a blank write", async () => {
  const h = harness();
  await h.flush();
  await h.generate();
  h.el("#gen-copy").listeners.get("click")();
  await h.flush();
  assert.deepEqual(h.clipboardWrites, ["Private-Canary-1"]);

  h.context.navigator.clipboard.value = "FOREIGN-OWNER";
  h.windowListeners.get("pagehide")();
  h.el("#lock-btn").listeners.get("click")();
  h.runTimers();
  await h.flush();
  assert.deepEqual(h.clipboardWrites, ["Private-Canary-1"]);
  assert.equal(h.context.navigator.clipboard.value, "FOREIGN-OWNER");
});

test("popup source keeps only explicit browser copies and no owning timer", () => {
  const source = fs.readFileSync(POPUP, "utf8");
  assert.equal(
    source.includes('writeText?.("")') || source.includes('writeText("")'),
    false,
    "blank clipboard clear must be removed",
  );
  assert.equal(source.includes("clipboardTimer"), false);
  assert.match(source, /clipboard\.writeText\(value\)/);
  assert.match(source, /浏览器无法保证自动清除/);
});
