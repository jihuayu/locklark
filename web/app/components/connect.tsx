"use client";
import { useState, type FormEvent } from "react";
export function Connect() {
  const [code, setCode] = useState("");
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const trimmedLength = code.trim().length;
  const isReady = trimmedLength === 64;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const entered = code.trim();
    setCode("");
    setReveal(false);
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
          "连接码无效、已使用或已过期。请重新启动管理界面以获取新的连接码。",
        );
        return;
      }
      window.location.replace("/");
    } catch {
      setError("无法连接本机管理服务，请确认后台服务仍在运行。");
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="connect-shell">
      <section className="welcome">
        <div className="welcome-top">
          <div className="brand">
            <span className="brand-mark" aria-hidden="true">
              L
            </span>
            <span>Locklark</span>
            <span className="brand-tag">Local Console</span>
          </div>
          <p className="eyebrow">团队目录与设备审阅</p>
          <h1>
            你的团队，
            <br />
            一目了然。
          </h1>
          <p className="welcome-lead">
            在本地安全审阅已验证的团队成员、授权设备与目录检查点状态。
          </p>
          <ul className="welcome-highlights" aria-label="安全特性">
            <li>
              <span className="highlight-dot" aria-hidden="true" />
              <div>
                <strong>本地签名核验</strong>
                <span>目录快照与检查点均经本机密码学签名验证后呈现</span>
              </div>
            </li>
            <li>
              <span className="highlight-dot" aria-hidden="true" />
              <div>
                <strong>单次时效凭证</strong>
                <span>连接码仅限单次兑换，5 分钟内有效，会话严格绑定本机</span>
              </div>
            </li>
          </ul>
        </div>
        <div className="welcome-note">
          <span className="status-dot" aria-hidden="true" />
          <span>密钥与金库内容始终由原生应用独立保管，Web 端仅只读审阅元数据</span>
        </div>
      </section>
      <section className="connect-panel" aria-labelledby="connect-title">
        <div className="connect-card">
          <div className="connect-card-header">
            <span className="step-label">连接本机服务</span>
            <h2 id="connect-title">欢迎回来</h2>
            <p>
              粘贴启动管理界面时生成的 64 位连接码。连接码仅能使用一次，5 分钟内有效。
            </p>
          </div>
          <form onSubmit={submit}>
            <div className="field-header">
              <label htmlFor="connection-code">本机连接码</label>
              <span
                className={
                  isReady
                    ? "code-counter ready"
                    : trimmedLength > 0
                      ? "code-counter active"
                      : "code-counter"
                }
                aria-live="polite"
              >
                已输入 {trimmedLength} / 64 位
              </span>
            </div>
            <div className="input-wrapper">
              <input
                id="connection-code"
                name="code"
                type={reveal ? "text" : "password"}
                autoComplete="off"
                spellCheck={false}
                value={code}
                onChange={(e) => {
                  setCode(e.target.value);
                  if (error) setError("");
                }}
                maxLength={128}
                required
                disabled={busy}
                placeholder="粘贴 64 位本机连接码"
              />
              {code.length > 0 ? (
                <div className="input-actions">
                  <button
                    type="button"
                    className="ghost-action"
                    onClick={() => setReveal((prev) => !prev)}
                    disabled={busy}
                  >
                    {reveal ? "隐藏" : "显示"}
                  </button>
                  <button
                    type="button"
                    className="ghost-action"
                    onClick={() => {
                      setCode("");
                      setError("");
                    }}
                    disabled={busy}
                  >
                    清空
                  </button>
                </div>
              ) : null}
            </div>
            <button className="primary" disabled={busy || !isReady}>
              {busy ? "正在验证并连接…" : "连接管理界面"}
            </button>
          </form>
          {error ? (
            <p className="form-error" role="alert">
              {error}
            </p>
          ) : null}
          <div className="help-note">
            <strong>连接码在哪里获取？</strong>
            <p>
              在本机运行管理服务与 Web 启动命令后，终端窗口会输出一次性连接码。本页面永远不会要求输入主密码或 Secret Key。
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
