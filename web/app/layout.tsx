import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "Locklark · 团队管理",
  description: "查看本机已验证的团队目录和设备状态。",
};
export default function Layout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
