import { sessionExpiry, readSummary } from "../lib/server";
import { Connect } from "./components/connect";
import { Dashboard } from "./components/dashboard";
export const dynamic = "force-dynamic";
export default async function Page() {
  const expires = await sessionExpiry();
  if (!expires) return <Connect />;
  const summary = await readSummary().catch(() => null);
  return <Dashboard initial={summary} expires={expires} />;
}
