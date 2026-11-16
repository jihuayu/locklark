// Owned HTTPS website only. This fixture has no vault, native approval, or
// password mutation API: account changes require its ordinary website forms.
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { createServer } from "node:https";

export const ROTATION_SITE_HOST = "login.locklark.test";
const COOKIE = "__Host-locklark-rotation";
const BODY_LIMIT = 4096;
const COUNTER_LIMIT = 65535;
const SESSION_TTL = 5 * 60 * 1000;
const escapeHTML = (value) => value.replace(/[&<>"']/g, (character) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
const digest = (value) => createHash("sha256").update(value).digest();
const equal = (left, right) => left.length === right.length && timingSafeEqual(left, right);
const validPassword = (value) => typeof value === "string" && value.isWellFormed() &&
  Buffer.byteLength(value) >= 4 && Buffer.byteLength(value) <= 256 && !/[\0\r\n]/.test(value);

class FormRefusal extends Error {
  constructor(status = 400) { super("Owned website form refused"); this.status = status; }
}

// At most BODY_LIMIT bytes are retained. An early refusal closes this request's
// connection instead of consuming an unbounded upload or accepting a next one.
function readForm(request) {
  if (!/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(request.headers["content-type"] || ""))
    return Promise.reject(new FormRefusal(415));
  const length = request.headers["content-length"];
  if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > BODY_LIMIT))
    return Promise.reject(new FormRefusal(413));
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const clean = () => {
      request.removeListener("data", data);
      request.removeListener("end", end);
      request.removeListener("aborted", aborted);
      request.removeListener("error", aborted);
      for (const chunk of chunks) chunk.fill(0);
    };
    const fail = (status) => {
      request.pause();
      clean();
      reject(new FormRefusal(status));
    };
    const data = (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT) { fail(413); return; }
      chunks.push(Buffer.from(chunk));
    };
    const aborted = () => fail(400);
    const end = () => {
      const bytes = Buffer.concat(chunks);
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (/%(?![0-9a-f]{2})/i.test(text)) throw new FormRefusal();
        resolve(new URLSearchParams(text));
      } catch { reject(new FormRefusal()); }
      finally { bytes.fill(0); clean(); }
    };
    request.on("data", data);
    request.once("end", end);
    request.once("aborted", aborted);
    request.once("error", aborted);
  });
}

// key/cert are owned fixture TLS material supplied by the controller. The
// returned endpoints are private controller data; snapshots never contain them.
export function createBrowserRotationSite({ key, cert, onSnapshot = () => {} }) {
  if (typeof onSnapshot !== "function") throw Error("Owned website observer required");
  let account = null, session = null, authority = "", origin = "", started = false, closed = false;
  const sockets = new Set();
  const counts = {
    tlsConnections: 0, requests: 0, registrations: 0, loginAccepted: 0,
    loginRejected: 0, passwordChanges: 0, changeRejected: 0,
    basicAccepted: 0, basicRejected: 0, requestRefused: 0, observerFailures: 0,
    countersCapped: false,
  };
  const snapshot = () => Object.freeze({ ...counts, accountRegistered: account !== null, closed });
  const record = (name) => {
    if (counts[name] < COUNTER_LIMIT) counts[name]++;
    else counts.countersCapped = true;
    try { onSnapshot(snapshot()); }
    catch {
      if (counts.observerFailures < COUNTER_LIMIT) counts.observerFailures++;
      else counts.countersCapped = true;
    }
  };
  const newSession = (response, authenticated) => {
    const token = randomBytes(32).toString("base64url");
    session = { tokenHash: digest(token), csrf: randomBytes(32).toString("hex"), authenticated, until: Date.now() + SESSION_TTL };
    response.setHeader("Set-Cookie", `${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict`);
  };
  const currentSession = (request, authenticated = false) => {
    const values = (request.headers.cookie || "").split(";").map((part) => part.trim())
      .filter((part) => part.startsWith(COOKIE + "="));
    if (values.length !== 1 || !session || Date.now() >= session.until ||
        (authenticated && !session.authenticated)) return null;
    const token = values[0].slice(COOKIE.length + 1);
    return /^[A-Za-z0-9_-]{43}$/.test(token) && equal(digest(token), session.tokenHash) ? session : null;
  };
  const verify = (username, password) => {
    if (!account || username !== account.username || !validPassword(password)) return false;
    const hash = scryptSync(password, account.salt, 32);
    try { return equal(hash, account.hash); } finally { hash.fill(0); }
  };
  const setPassword = (password) => {
    const salt = randomBytes(16);
    const hash = scryptSync(password, salt, 32);
    if (account.hash) account.hash.fill(0);
    if (account.salt) account.salt.fill(0);
    account.salt = salt;
    account.hash = hash;
  };
  const page = (response, title, body, script = "") => {
    const nonce = randomBytes(16).toString("base64");
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.setHeader("Content-Security-Policy", `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
    response.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Locklark acceptance · ${title}</title><body><h1>${title}</h1>${body}${script ? `<script nonce="${nonce}">${script}</script>` : ""}</body></html>`);
  };
  const form = (kind) => {
    const changing = kind === "change-password", registering = kind === "register";
    // The extension captures writable username fields. This presentation does
    // not select the account: the authenticated POST still checks its username.
    return `<form id="${kind}" method="post" action="/${kind}"><input type="hidden" name="csrf" value="${session.csrf}"><label>Username<input id="username" name="username" autocomplete="username" required${changing ? ` value="${escapeHTML(account.username)}"` : ""}></label><label>${changing ? "New password" : "Password"}<input id="${changing ? "new-password" : "password"}" name="password" type="password" autocomplete="${changing || registering ? "new-password" : "current-password"}" required></label>${changing || registering ? '<label>Confirm password<input id="confirm-password" name="confirm" type="password" autocomplete="new-password" required></label>' : ""}<button type="submit">${changing ? "Change password" : registering ? "Register" : "Sign in"}</button></form><p id="change-result" role="status"></p>`;
  };
  // The fetch performs the real form POST while retaining the document in
  // which the extension generated/staged the new password for native save.
  const changeScript = `document.querySelector("form").addEventListener("submit",async event=>{event.preventDefault();const form=event.currentTarget;const status=document.querySelector("#change-result");try{const response=await fetch(form.action,{method:"POST",body:new URLSearchParams(new FormData(form)),credentials:"same-origin",headers:{Accept:"application/json"}});const result=await response.json();const changed=response.ok&&result.changed===true;status.textContent=changed?"Password changed":"Password change refused";document.body.dataset.rotationResult=changed?"changed":"refused";}catch{status.textContent="Password change refused";document.body.dataset.rotationResult="refused";}});`;
  const refuse = (request, response, status, counter = "requestRefused") => {
    record(counter);
    request.pause();
    response.statusCode = status;
    response.setHeader("Connection", "close");
    response.setHeader("Content-Type", "application/json");
    response.once("finish", () => request.destroy());
    response.end('{"accepted":false}');
  };
  const handler = async (request, response) => {
    record("requests");
    request.on("error", () => {});
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Referrer-Policy", "same-origin");
    response.setHeader("X-Content-Type-Options", "nosniff");
    if (closed || request.headers.host !== authority) { refuse(request, response, 421); return; }
    const path = request.url;
    if (request.method === "GET" && ["/register", "/login"].includes(path)) {
      if (path === "/register" && account) { refuse(request, response, 409); return; }
      newSession(response, false);
      page(response, path === "/register" ? "Register" : "Sign in", form(path.slice(1)));
      return;
    }
    if (request.method === "GET" && path === "/change-password") {
      if (!currentSession(request, true)) { refuse(request, response, 401); return; }
      page(response, "Change password", form("change-password"), changeScript);
      return;
    }
    if (request.method === "GET" && path === "/credential") {
      let accepted = false;
      const header = request.headers.authorization || "";
      if (header.length <= 1024 && /^Basic [A-Za-z0-9+/]+={0,2}$/.test(header)) {
        const encoded = header.slice(6), bytes = Buffer.from(encoded, "base64");
        try {
          if (bytes.toString("base64") === encoded) {
            const pair = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
            const colon = pair.indexOf(":");
            if (colon > 0) accepted = verify(pair.slice(0, colon), pair.slice(colon + 1));
          }
        } catch { accepted = false; }
        finally { bytes.fill(0); }
      }
      record(accepted ? "basicAccepted" : "basicRejected");
      response.statusCode = accepted ? 200 : 401;
      if (!accepted) response.setHeader("WWW-Authenticate", 'Basic realm="Locklark owned rotation", charset="UTF-8"');
      response.setHeader("Content-Type", "application/json");
      response.end(accepted ? '{"authenticated":true}' : '{"authenticated":false}');
      return;
    }
    if (request.method !== "POST" || !["/register", "/login", "/change-password"].includes(path)) {
      refuse(request, response, 404); return;
    }
    const counter = path === "/change-password" ? "changeRejected" : path === "/login" ? "loginRejected" : "requestRefused";
    if (request.headers.origin !== origin) { refuse(request, response, 403, counter); return; }
    try {
      const fields = await readForm(request);
      const allowed = path === "/login" ? ["csrf", "username", "password"] : ["csrf", "username", "password", "confirm"];
      if ([...fields.keys()].some((key) => !allowed.includes(key) || fields.getAll(key).length !== 1) ||
          allowed.some((key) => !fields.has(key))) throw new FormRefusal();
      const active = currentSession(request, path === "/change-password");
      const csrf = fields.get("csrf");
      if (!active || !/^[a-f0-9]{64}$/.test(csrf) || !equal(Buffer.from(csrf), Buffer.from(active.csrf)))
        throw new FormRefusal(403);
      const username = fields.get("username"), password = fields.get("password");
      if (!/^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$/.test(username) || !validPassword(password)) throw new FormRefusal();
      if (path !== "/login" && fields.get("confirm") !== password) throw new FormRefusal();
      if (path === "/register") {
        if (account) throw new FormRefusal(409);
        account = { username };
        setPassword(password);
        newSession(response, true);
        record("registrations");
        response.statusCode = 201;
        page(response, "Account created", '<a href="/login">Sign in</a>');
      } else if (path === "/login") {
        if (!verify(username, password)) throw new FormRefusal(401);
        newSession(response, true);
        record("loginAccepted");
        response.writeHead(303, { Location: "/change-password" });
        response.end();
      } else {
        if (username !== account.username) throw new FormRefusal(403);
        setPassword(password);
        newSession(response, true);
        record("passwordChanges");
        if (request.headers.accept === "application/json") {
          response.setHeader("Content-Type", "application/json");
          response.end('{"changed":true}');
        } else page(response, "Password changed", '<a href="/change-password">Account</a>');
      }
    } catch (error) {
      refuse(request, response, error instanceof FormRefusal ? error.status : 500, counter);
    }
  };
  const server = createServer({ key, cert, minVersion: "TLSv1.3", maxHeaderSize: 4096,
    requestTimeout: 5000, headersTimeout: 5000, keepAliveTimeout: 1000 }, handler);
  server.maxConnections = 16;
  server.maxRequestsPerSocket = 32;
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.on("secureConnection", () => record("tlsConnections"));
  return Object.freeze({
    snapshot,
    async listen() {
      if (started || closed) throw Error("Owned website cannot listen again");
      started = true;
      await new Promise((resolve, reject) => {
        const failed = () => reject(Error("Owned website listen failed"));
        server.once("error", failed);
        server.listen(0, "127.0.0.1", () => { server.removeListener("error", failed); resolve(); });
      });
      authority = `${ROTATION_SITE_HOST}:${server.address().port}`;
      origin = `https://${authority}`;
      return Object.freeze({ origin, registerURL: origin + "/register", loginURL: origin + "/login",
        changeURL: origin + "/change-password", targetURL: origin + "/credential" });
    },
    async close() {
      if (closed) return;
      closed = true;
      session = null;
      if (account) { account.hash?.fill(0); account.salt?.fill(0); account = null; }
      await new Promise((resolve) => {
        server.close(() => resolve());
        for (const socket of sockets) socket.destroy();
      });
    },
  });
}
