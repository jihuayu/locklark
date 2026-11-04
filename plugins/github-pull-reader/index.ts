// Built-in proposer. No vault, credential, HTTP or shell API is needed.
// The host independently validates this proposal against its trusted grant.
async function propose(): Promise<void> {
  const reader = Bun.stdin.stream().getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > 4096) throw new Error();
    chunks.push(value);
  }
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  // The tiny protocol only accepts these two literal keys, in either order.
  // Validating its grammar before JSON.parse also rules out duplicate keys.
  if (!/^\s*\{\s*(?:"repo"\s*:\s*"[1-9][0-9]{0,18}"\s*,\s*"number"\s*:\s*[1-9][0-9]{0,9}|"number"\s*:\s*[1-9][0-9]{0,9}\s*,\s*"repo"\s*:\s*"[1-9][0-9]{0,18}")\s*\}\s*$/.test(raw)) throw new Error();
  const { repo, number } = JSON.parse(raw);
  if (number > 2147483647 || BigInt(repo) > 9223372036854775807n) throw new Error();
  console.log(JSON.stringify({ v: 1, action: "github.pulls.get", repo, number }));
}
try { await propose(); } catch { console.error("invalid pull request arguments"); process.exitCode = 1; }
