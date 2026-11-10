"use client";
import { useEffect, useState } from "react";
import { parseSummary, type Summary } from "../../lib/summary";
type Tab = "overview" | "members" | "devices" | "connection";
const tabs: { id: Tab; label: string; subtitle: string; mark: string }[] = [
  {
    id: "overview",
    label: "概览",
    subtitle: "本机已验证的团队目录快照与安全状态摘要",
    mark: "◈",
  },
  {
    id: "members",
    label: "团队成员",
    subtitle: "当前目录中已登记的成员身份与角色权限",
    mark: "◇",
  },
  {
    id: "devices",
    label: "设备",
    subtitle: "与团队成员关联的已登记终端设备列表",
    mark: "▣",
  },
  {
    id: "connection",
    label: "连接与安全",
    subtitle: "当前本机只读会话范围、信任边界与检查点详情",
    mark: "⌁",
  },
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
    initial ? "" : "无法验证当前本地目录，请检查本机管理服务。",
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
  const writerCount = members.filter((m) => m.role === "writer").length;
  const readerCount = members.length - writerCount;
  const devices = members.flatMap((member) =>
    member.devices.map((id) => ({ id, member: member.id, role: member.role })),
  );
  const needle = query.trim().toLowerCase();
  const filteredMembers = members.filter((member) =>
    member.id.toLowerCase().includes(needle),
  );
  const filteredDevices = devices.filter(
    (device) =>
      device.id.toLowerCase().includes(needle) ||
      device.member.toLowerCase().includes(needle),
  );
  const activeTab = tabs.find((item) => item.id === tab) ?? tabs[0];
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
          <span className="brand-mark" aria-hidden="true">
            L
          </span>
          <span>Locklark</span>
        </div>
        <div className="workspace">
          <span className="workspace-icon" aria-hidden="true">
            团
          </span>
          <div>
            <strong>团队工作区</strong>
            <span>本机只读控制台</span>
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
          <div className="session-indicator">
            <span className="status-dot" aria-hidden="true" />
            <span>只读管理会话</span>
          </div>
          <button onClick={disconnect} disabled={busy}>
            断开连接
          </button>
        </div>
      </aside>
      <main className="main-panel">
        <header className="page-header">
          <div>
            <p className="eyebrow">工作区 / {activeTab.label}</p>
            <h1>{activeTab.label}</h1>
            <p className="page-subtitle">{activeTab.subtitle}</p>
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
            <span className="empty-icon" aria-hidden="true">
              ◇
            </span>
            <h2>暂时无法取得可信状态</h2>
            <p>
              请检查本机管理服务与目录文件后点击“刷新状态”。为确保安全，此处不会沿用旧的成员缓存。
            </p>
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
              <span className="verification-meta">
                检查点版本 <strong>v{summary.checkpoint.version}</strong>
                <span className="meta-sep" aria-hidden="true">
                  ·
                </span>
                观测时间{" "}
                <time dateTime={summary.observedAt}>
                  {summary.observedAt.replace("T", " ").replace("Z", " UTC")}
                </time>
              </span>
            </div>
            {tab === "overview" ? (
              <>
                <section className="stats-grid" aria-label="团队概览">
                  <article className="stat-card">
                    <p>团队成员</p>
                    <strong>{members.length}</strong>
                    <span>
                      {writerCount} 名可写 · {readerCount} 名只读
                    </span>
                  </article>
                  <article className="stat-card">
                    <p>已登记设备</p>
                    <strong>{devices.length}</strong>
                    <span>与当前目录成员绑定的可信终端</span>
                  </article>
                  <article className="stat-card">
                    <p>目录版本</p>
                    <strong>v{summary.checkpoint.version}</strong>
                    <span>密码学签名与本地历史链验证通过</span>
                  </article>
                </section>
                <section className="panel overview-panel">
                  <div className="overview-main">
                    <p className="eyebrow">工作区状态</p>
                    <h2>
                      {summary.mode === "frozen"
                        ? "团队目录已暂停使用"
                        : "查看团队的访问结构"}
                    </h2>
                    <p>
                      成员与设备名单直接读取自本机已验证的团队目录快照。邀请成员、变更角色权限或吊销设备均须在受信任的原生客户端中完成确认。
                    </p>
                    <div className="overview-actions">
                      <button
                        className="secondary"
                        onClick={() => select("members")}
                      >
                        查看团队成员
                      </button>
                      <button
                        className="secondary"
                        onClick={() => select("devices")}
                      >
                        查看已登记设备
                      </button>
                    </div>
                  </div>
                  <div className="scope-note">
                    <strong>这份状态说明什么？</strong>
                    <p>
                      当前验证结果仅证明本机目录快照及检查点链完整有效，不代表已与远端服务器完成实时同步，也不包含任何金库加密内容。
                    </p>
                  </div>
                </section>
              </>
            ) : null}
            {tab === "members" ? (
              <section className="panel">
                <div className="table-toolbar">
                  <div>
                    <h2>
                      团队成员{" "}
                      <span className="count-pill">
                        {needle
                          ? `${filteredMembers.length} / ${members.length}`
                          : members.length}
                      </span>
                    </h2>
                  </div>
                  <div className="search-controls">
                    <label className="search-label">
                      搜索成员 ID
                      <input
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="输入成员 ID 筛选"
                        maxLength={64}
                      />
                    </label>
                    {query ? (
                      <button
                        type="button"
                        className="ghost-action clear-search"
                        onClick={() => setQuery("")}
                      >
                        清除
                      </button>
                    ) : null}
                  </div>
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
                            <code className="id-code">{member.id}</code>
                          </td>
                          <td>
                            <span
                              className={
                                member.role === "writer"
                                  ? "role-badge writer"
                                  : "role-badge reader"
                              }
                            >
                              {roleName(member.role)}
                            </span>
                          </td>
                          <td className="tabular-cell">
                            {member.devices.length} 台
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredMembers.length === 0 ? (
                  <div className="table-empty">
                    <p>没有匹配的成员</p>
                    {query ? (
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => setQuery("")}
                      >
                        清除筛选条件
                      </button>
                    ) : null}
                  </div>
                ) : null}
              </section>
            ) : null}
            {tab === "devices" ? (
              <section className="panel">
                <div className="table-toolbar">
                  <div>
                    <h2>
                      已登记设备{" "}
                      <span className="count-pill">
                        {needle
                          ? `${filteredDevices.length} / ${devices.length}`
                          : devices.length}
                      </span>
                    </h2>
                  </div>
                  <div className="search-controls">
                    <label className="search-label">
                      搜索设备或成员 ID
                      <input
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="输入设备或成员 ID 筛选"
                        maxLength={64}
                      />
                    </label>
                    {query ? (
                      <button
                        type="button"
                        className="ghost-action clear-search"
                        onClick={() => setQuery("")}
                      >
                        清除
                      </button>
                    ) : null}
                  </div>
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
                            <code className="id-code">{device.id}</code>
                          </td>
                          <td>
                            <code className="id-code">{device.member}</code>
                          </td>
                          <td>
                            <span
                              className={
                                device.role === "writer"
                                  ? "role-badge writer"
                                  : "role-badge reader"
                              }
                            >
                              {roleName(device.role)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredDevices.length === 0 ? (
                  <div className="table-empty">
                    <p>没有匹配的设备</p>
                    {query ? (
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => setQuery("")}
                      >
                        清除筛选条件
                      </button>
                    ) : null}
                  </div>
                ) : null}
              </section>
            ) : null}
            {tab === "connection" ? (
              <section className="panel security-panel">
                <h2>当前管理连接</h2>
                <p>
                  本页面运行在严格的本机只读沙箱内，不持有任何金库解锁密钥，也无法发起或批准成员与设备变更。
                </p>
                <dl>
                  <div>
                    <dt>连接范围</dt>
                    <dd>本机回环（127.0.0.1）· 团队目录元数据只读</dd>
                  </div>
                  <div>
                    <dt>会话有效期</dt>
                    <dd>
                      连接后 30 分钟（截止{" "}
                      <span className="tabular-cell">
                        {new Date(expires)
                          .toISOString()
                          .replace("T", " ")
                          .slice(0, 19)}{" "}
                        UTC
                      </span>
                      ）
                    </dd>
                  </div>
                  <div>
                    <dt>金库密钥隔离</dt>
                    <dd>由原生客户端与操作系统密钥链独立保护，永不导出至 Web</dd>
                  </div>
                </dl>
                <details>
                  <summary>查看本地检查点</summary>
                  <dl>
                    <div>
                      <dt>目录范围</dt>
                      <dd>
                        <code className="id-code">
                          {summary.checkpoint.scope}
                        </code>
                      </dd>
                    </div>
                    <div>
                      <dt>检查点摘要</dt>
                      <dd>
                        <code className="id-code">
                          {summary.checkpoint.hash}
                        </code>
                      </dd>
                    </div>
                  </dl>
                </details>
                <button
                  className="secondary danger-outline"
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
          Locklark · 金库加密操作、成员变更与系统解锁均在原生应用中完成
        </footer>
      </main>
    </div>
  );
}
