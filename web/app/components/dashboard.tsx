"use client";
import { useEffect, useState } from "react";
import { parseSummary, type Summary } from "../../lib/summary";
type Tab = "overview" | "members" | "devices" | "connection";
const tabs: { id: Tab; label: string; mark: string }[] = [
  { id: "overview", label: "概览", mark: "◈" },
  { id: "members", label: "团队成员", mark: "◇" },
  { id: "devices", label: "设备", mark: "▣" },
  { id: "connection", label: "连接与安全", mark: "⌁" },
];
const roleName = (role: string) =>
  role === "writer" ? "可写成员" : "只读成员";
export function Dashboard({
  initial,
  expires,
}: {
  initial: Summary | null;
  expires: number;
}) {
  const [summary, setSummary] = useState(initial);
  const [tab, setTab] = useState<Tab>("overview");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(
    initial ? "" : "无法验证当前本地目录，请检查管理服务。",
  );
  useEffect(() => {
    const timer = window.setTimeout(
      () => {
        setSummary(null);
        setError("管理会话已到期，请重新连接。");
      },
      Math.max(0, expires - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, [expires]);
  const members = summary?.members ?? [];
  const devices = members.flatMap((member) =>
    member.devices.map((id) => ({ id, member: member.id, role: member.role })),
  );
  const needle = query.trim().toLowerCase();
  const filteredMembers = members.filter((member) =>
    member.id.includes(needle),
  );
  const filteredDevices = devices.filter(
    (device) => device.id.includes(needle) || device.member.includes(needle),
  );
  async function refresh() {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/summary", { cache: "no-store" });
      if (response.status === 401) {
        window.location.replace("/");
        return;
      }
      if (!response.ok) throw new Error("unavailable");
      setSummary(parseSummary(await response.json()));
    } catch {
      setSummary(null);
      setError("无法验证当前本地目录。请检查管理服务与可信目录文件，再重试。");
    } finally {
      setBusy(false);
    }
  }
  async function disconnect() {
    setBusy(true);
    setSummary(null);
    setError("");
    try {
      const response = await fetch("/api/session", {
        method: "DELETE",
        cache: "no-store",
      });
      if (!response.ok) throw new Error("disconnect");
      window.location.replace("/");
    } catch {
      setError("断开连接未完成，请重试。");
      setBusy(false);
    }
  }
  function select(next: Tab) {
    setTab(next);
    setQuery("");
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">L</span>Locklark
        </div>
        <div className="workspace">
          <span className="workspace-icon">团</span>
          <div>
            <strong>团队工作区</strong>
            <span>本机管理</span>
          </div>
        </div>
        <nav aria-label="管理导航">
          {tabs.map((item) => (
            <button
              key={item.id}
              className={tab === item.id ? "nav-item selected" : "nav-item"}
              aria-current={tab === item.id ? "page" : undefined}
              onClick={() => select(item.id)}
            >
              <span aria-hidden="true">{item.mark}</span>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="status-dot" />
          只读管理会话
          <button onClick={disconnect} disabled={busy}>
            断开连接
          </button>
        </div>
      </aside>
      <main className="main-panel">
        <header className="page-header">
          <div>
            <p className="eyebrow">
              工作区 / {tabs.find((item) => item.id === tab)?.label}
            </p>
            <h1>{tabs.find((item) => item.id === tab)?.label}</h1>
          </div>
          <button className="secondary" disabled={busy} onClick={refresh}>
            {busy ? "正在读取…" : "刷新状态"}
          </button>
        </header>
        {error ? (
          <div className="error-banner" role="alert">
            {error}
          </div>
        ) : null}
        {!summary ? (
          <section className="empty-state">
            <span aria-hidden="true">◇</span>
            <h2>暂时无法取得可信状态</h2>
            <p>检查本机管理服务后刷新。这里不会沿用上次读取的成员列表。</p>
          </section>
        ) : (
          <>
            <div className="verification-line">
              <span
                className={
                  summary.mode === "frozen" ? "badge warning" : "badge"
                }
              >
                {summary.mode === "frozen" ? "目录已冻结" : "本地目录已验证"}
              </span>
              <span>
                版本 {summary.checkpoint.version} · 读取于{" "}
                {summary.observedAt.replace("T", " ").replace("Z", " UTC")}
              </span>
            </div>
            {tab === "overview" ? (
              <>
                <section className="stats-grid" aria-label="团队概览">
                  <article className="stat-card">
                    <p>团队成员</p>
                    <strong>{members.length}</strong>
                    <span>当前目录中登记的成员</span>
                  </article>
                  <article className="stat-card">
                    <p>已登记设备</p>
                    <strong>{devices.length}</strong>
                    <span>与团队成员关联的设备</span>
                  </article>
                  <article className="stat-card">
                    <p>目录版本</p>
                    <strong>v{summary.checkpoint.version}</strong>
                    <span>签名与本地历史验证通过</span>
                  </article>
                </section>
                <section className="panel overview-panel">
                  <div>
                    <p className="eyebrow">工作区状态</p>
                    <h2>
                      {summary.mode === "frozen"
                        ? "团队目录已暂停使用"
                        : "查看团队的访问结构"}
                    </h2>
                    <p>
                      成员与设备信息来自本机已验证的团队目录。邀请、变更权限与吊销需要在可信原生端确认。
                    </p>
                    <button
                      className="secondary"
                      onClick={() => select("members")}
                    >
                      查看团队成员
                    </button>
                  </div>
                  <div className="scope-note">
                    <strong>这份状态说明什么？</strong>
                    <p>
                      验证结果对应当前本地目录，不证明远端的最新状态，也不代表同步已经完成。
                    </p>
                  </div>
                </section>
              </>
            ) : null}
            {tab === "members" ? (
              <section className="panel">
                <div className="table-toolbar">
                  <h2>
                    团队成员 <span>{members.length}</span>
                  </h2>
                  <label className="search-label">
                    搜索成员 ID
                    <input
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="输入成员 ID"
                      maxLength={64}
                    />
                  </label>
                </div>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>成员 ID</th>
                        <th>目录角色</th>
                        <th>已登记设备</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredMembers.map((member) => (
                        <tr key={member.id}>
                          <td>
                            <code>{member.id}</code>
                          </td>
                          <td>
                            <span className="role-badge">
                              {roleName(member.role)}
                            </span>
                          </td>
                          <td>{member.devices.length} 台</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredMembers.length === 0 ? (
                  <p className="table-empty">没有匹配的成员</p>
                ) : null}
              </section>
            ) : null}
            {tab === "devices" ? (
              <section className="panel">
                <div className="table-toolbar">
                  <h2>
                    已登记设备 <span>{devices.length}</span>
                  </h2>
                  <label className="search-label">
                    搜索设备或成员 ID
                    <input
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="输入设备或成员 ID"
                      maxLength={64}
                    />
                  </label>
                </div>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>设备 ID</th>
                        <th>所属成员</th>
                        <th>成员角色</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredDevices.map((device) => (
                        <tr key={device.id}>
                          <td>
                            <code>{device.id}</code>
                          </td>
                          <td>
                            <code>{device.member}</code>
                          </td>
                          <td>{roleName(device.role)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredDevices.length === 0 ? (
                  <p className="table-empty">没有匹配的设备</p>
                ) : null}
              </section>
            ) : null}
            {tab === "connection" ? (
              <section className="panel security-panel">
                <h2>当前管理连接</h2>
                <dl>
                  <div>
                    <dt>连接范围</dt>
                    <dd>本机 · 团队元数据只读</dd>
                  </div>
                  <div>
                    <dt>会话有效期</dt>
                    <dd>
                      连接后 30 分钟（截止{" "}
                      {new Date(expires)
                        .toISOString()
                        .replace("T", " ")
                        .slice(0, 19)}{" "}
                      UTC）
                    </dd>
                  </div>
                  <div>
                    <dt>金库密钥</dt>
                    <dd>由原生应用与系统密钥管理工具保护</dd>
                  </div>
                </dl>
                <p>本页面不持有金库解锁材料，也不能批准成员或设备变更。</p>
                <details>
                  <summary>查看本地检查点</summary>
                  <dl>
                    <div>
                      <dt>目录范围</dt>
                      <dd>
                        <code>{summary.checkpoint.scope}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>检查点摘要</dt>
                      <dd>
                        <code>{summary.checkpoint.hash}</code>
                      </dd>
                    </div>
                  </dl>
                </details>
                <button
                  className="secondary"
                  onClick={disconnect}
                  disabled={busy}
                >
                  结束当前管理会话
                </button>
              </section>
            ) : null}
          </>
        )}
        <footer className="page-footer">
          Locklark · 金库操作与系统解锁在原生应用中完成
        </footer>
      </main>
    </div>
  );
}
