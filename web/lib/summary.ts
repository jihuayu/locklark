export type Member = {
  id: string;
  role: "reader" | "writer";
  devices: string[];
};
export type Summary = {
  version: 1;
  mode: "active" | "frozen";
  checkpoint: { scope: string; version: number; hash: string };
  observedAt: string;
  freshness: "local-verified";
  members: Member[];
};
const hex = (value: unknown, length: number): value is string =>
  typeof value === "string" && new RegExp(`^[0-9a-f]{${length}}$`).test(value);
export function parseSummary(raw: unknown): Summary {
  const s = raw as Summary;
  if (
    !s ||
    s.version !== 1 ||
    !["active", "frozen"].includes(s.mode) ||
    s.freshness !== "local-verified" ||
    !s.checkpoint ||
    !hex(s.checkpoint.scope, 64) ||
    !hex(s.checkpoint.hash, 64) ||
    !Number.isSafeInteger(s.checkpoint.version) ||
    s.checkpoint.version < 1 ||
    s.checkpoint.version > 1024 ||
    typeof s.observedAt !== "string" ||
    !Number.isFinite(Date.parse(s.observedAt)) ||
    !Array.isArray(s.members) ||
    s.members.length > 64
  )
    throw new Error("Management state could not be verified");
  const seen = new Set<string>();
  const members = s.members.map((member) => {
    if (
      !member ||
      !hex(member.id, 32) ||
      seen.has(member.id) ||
      !["reader", "writer"].includes(member.role) ||
      !Array.isArray(member.devices) ||
      member.devices.length > 64
    )
      throw new Error("Management state could not be verified");
    seen.add(member.id);
    const devices = member.devices.map((id) => {
      if (!hex(id, 32) || seen.has(id))
        throw new Error("Management state could not be verified");
      seen.add(id);
      return id;
    });
    return { id: member.id, role: member.role, devices };
  });
  if (s.mode === "frozen" && members.length !== 0)
    throw new Error("Management state could not be verified");
  // Explicit projection: unexpected upstream properties never reach the client.
  return {
    version: 1,
    mode: s.mode,
    checkpoint: {
      scope: s.checkpoint.scope,
      version: s.checkpoint.version,
      hash: s.checkpoint.hash,
    },
    observedAt: s.observedAt,
    freshness: "local-verified",
    members,
  };
}
