(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome;
  let busy = false;
  async function send(message) {
    try {
      const state = await api.runtime.sendMessage(message);
      if (!state) return;
      document.querySelector("#status").textContent = state.status;
      document.querySelector("#origin").textContent = state.origin;
      document.querySelector("#connect").disabled = state.connected || busy;
      document.querySelector("#refresh").disabled =
        !state.connected || state.pending || busy;
      const list = document.querySelector("#candidates");
      list.replaceChildren();
      for (const row of state.candidates) {
        const button = document.createElement("button");
        button.textContent = row.title;
        button.disabled = state.pending || busy;
        button.addEventListener(
          "click",
          () => void act({ type: "fill", id: row.id, revision: row.revision }),
        );
        list.append(button);
      }
    } catch {
      document.querySelector("#status").textContent =
        "连接不可用，请重新打开弹窗";
    }
  }
  async function act(message) {
    busy = true;
    await send(message);
    busy = false;
    await send({ type: "state" });
  }
  document
    .querySelector("#connect")
    .addEventListener("click", () => void act({ type: "connect" }));
  document
    .querySelector("#refresh")
    .addEventListener("click", () => void act({ type: "match" }));
  document
    .querySelector("#disconnect")
    .addEventListener("click", () => void act({ type: "disconnect" }));
  void send({ type: "state" });
  setInterval(() => void send({ type: "state" }), 500);
})();
