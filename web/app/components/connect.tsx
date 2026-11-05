"use client";
import { useState, type FormEvent } from "react";
export function Connect() {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const entered = code.trim();
    setCode("");
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: entered }),
        cache: "no-store",
      });
      if (!response.ok) {
        setError(
          "连接码无效、已使用或已过期。请重新启动管理界面，取得新的连接码。",
        );
        return;
      }
      window.location.replace("/");
    } catch {
      setError("无法连接本机管理服务，请确认服务仍在运行。");
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="connect-shell">
      <section className="welcome">
        <div className="brand">
          <span className="brand-mark">L</span>Locklark
        </div>
        <p className="eyebrow">团队管理</p>
        <h1>
          你的团队，
          <br />
          一目了然。
        </h1>
        <p>在这里查看团队成员、已登记设备和本地目录状态。</p>
        <div className="welcome-note">
          <span className="status-dot" />
          密钥与金库内容由原生应用保管
        </div>
      </section>
      <section className="connect-card" aria-labelledby="connect-title">
        <span className="step-label">连接本机服务</span>
        <h2 id="connect-title">欢迎回来</h2>
        <p>
          粘贴启动管理界面时显示的连接码。连接码仅能使用一次，5 分钟内有效。
        </p>
        <form onSubmit={submit}>
          <label htmlFor="connection-code">本机连接码</label>
          <input
            id="connection-code"
            name="code"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            maxLength={128}
            required
            disabled={busy}
            placeholder="粘贴连接码"
          />
          <button
            className="primary"
            disabled={busy || code.trim().length !== 64}
          >
            {busy ? "正在连接…" : "连接管理界面"}
          </button>
        </form>
        <p className="form-error" role="alert">
          {error}
        </p>
        <div className="help-note">
          <strong>连接码在哪里？</strong>
          <p>
            在本机运行管理服务与 Web
            启动命令后，启动窗口会显示连接码。此处无需输入主密码或 Secret Key。
          </p>
        </div>
      </section>
    </main>
  );
}
