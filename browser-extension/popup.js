(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome;
  let busy = false,
    renderedCandidates = "",
    lastState = null,
    actionGeneration = 0,
    requestSequence = 0,
    renderedSequence = 0;
  function text(selector, value) {
    const el = document.querySelector(selector);
    if (el.textContent !== value) el.textContent = value;
  }
  function render(state) {
    lastState = state;
    document.querySelector("#auto-login").checked = state.autoLogin !== false;
    document.querySelector("#passkey-save").checked =
      state.offerSavePasskeys !== false;
    document.querySelector("#passkey-use").checked =
      state.offerUsePasskeys !== false;
    text("#status", state.status);
    text("#origin", state.origin);
    text(
      "#save-warning",
      state.saveBlocked
        ? "保存结果未确认。请先在原生金库核实；需要继续保存时，先断开并重新连接。"
        : "",
    );
    document.querySelector("#connect").disabled = state.connected || busy;
    document.querySelector("#refresh").disabled =
      !state.connected || state.pending || busy;
    document.querySelector("#save-new").disabled =
      !state.connected || state.pending || state.saveBlocked || busy;
    document.querySelector("#cancel-otp").disabled = !state.otpPending;
    const list = document.querySelector("#candidates");
    const signature = JSON.stringify({
      rows: state.candidates,
      pending: state.pending,
      busy,
      saveBlocked: !!state.saveBlocked,
      loginOverrides: state.loginOverrides,
    });
    if (signature === renderedCandidates) return;
    renderedCandidates = signature;
    list.replaceChildren();
    for (const row of state.candidates) {
      const container = document.createElement("div");
      container.dataset.itemId = row.id;
      container.dataset.itemRevision = row.revision;
      const button = document.createElement("button");
      button.dataset.action = "fill";
      button.textContent = row.title || "（无标题）";
      button.disabled = state.pending || busy;
      button.addEventListener(
        "click",
        () => void act({ type: "fill", id: row.id, revision: row.revision }),
      );
      const update = document.createElement("button");
      update.dataset.action = "update";
      update.textContent = "更新此登录";
      update.disabled = state.pending || state.saveBlocked || busy;
      update.addEventListener(
        "click",
        () =>
          void act({
            type: "save-update",
            id: row.id,
            revision: row.revision,
          }),
      );
      const otp = document.createElement("button");
      otp.dataset.action = "otp";
      otp.textContent = "填充验证码";
      otp.disabled = state.pending || busy;
      otp.addEventListener(
        "click",
        () => void act({ type: "otp", id: row.id, revision: row.revision }),
      );
      const label = document.createElement("label"),
        toggle = document.createElement("input");
      toggle.type = "checkbox";
      toggle.disabled = state.pending || busy;
      toggle.checked = state.loginOverrides?.[row.id] !== false;
      toggle.addEventListener(
        "change",
        () =>
          void act({ type: "settings", id: row.id, enabled: toggle.checked }),
      );
      label.append(toggle, document.createTextNode(" 此登录允许自动提交"));
      container.append(button, update, otp, label);
      list.append(container);
    }
  }
  async function send(message, generation = actionGeneration) {
    const sequence = ++requestSequence;
    try {
      const state = await api.runtime.sendMessage(message);
      if (
        !state ||
        generation !== actionGeneration ||
        sequence <= renderedSequence
      )
        return;
      renderedSequence = sequence;
      render(state);
    } catch {
      if (generation !== actionGeneration || sequence <= renderedSequence)
        return;
      renderedSequence = sequence;
      render({
        connected: false,
        pending: false,
        candidates: [],
        origin: "",
        saveBlocked: !!lastState?.saveBlocked,
        status: "连接不可用，请重新打开弹窗",
      });
    }
  }
  async function act(message) {
    // Disconnect may interrupt a deferred action. Its generation also prevents
    // the old action's reply/finalizer from changing the next operation.
    if (busy && !["disconnect", "cancel-otp"].includes(message.type)) return;
    const generation = ++actionGeneration;
    busy = true;
    if (lastState) render(lastState);
    await send(message, generation);
    if (generation !== actionGeneration) return;
    await send({ type: "state" }, generation);
    if (generation !== actionGeneration) return;
    busy = false;
    if (lastState) render(lastState);
  }
  document
    .querySelector("#save-new")
    .addEventListener("click", () => void act({ type: "save-new" }));
  document
    .querySelector("#connect")
    .addEventListener("click", () => void act({ type: "connect" }));
  document
    .querySelector("#refresh")
    .addEventListener("click", () => void act({ type: "match" }));
  document
    .querySelector("#disconnect")
    .addEventListener("click", () => void act({ type: "disconnect" }));
  document
    .querySelector("#cancel-otp")
    .addEventListener("click", () => void act({ type: "cancel-otp" }));
  document
    .querySelector("#auto-login")
    .addEventListener(
      "change",
      (event) =>
        void act({ type: "settings", autoLogin: event.target.checked }),
    );
  document
    .querySelector("#passkey-save")
    .addEventListener(
      "change",
      (event) =>
        void act({ type: "settings", offerSavePasskeys: event.target.checked }),
    );
  document
    .querySelector("#passkey-use")
    .addEventListener(
      "change",
      (event) =>
        void act({ type: "settings", offerUsePasskeys: event.target.checked }),
    );
  void send({ type: "state" });
  setInterval(() => void send({ type: "state" }), 500);
})();
