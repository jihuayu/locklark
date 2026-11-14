// Fixed outermost boundary for the normal native acceptance entry. Primary
// and privacy diagnostics are already sanitized before they reach this catch;
// the raw exception, stack, and paths are deliberately never printed.
export async function runNativeMain(main) {
  try {
    await main();
  } catch {
    console.error("Native browser acceptance failed");
    process.exitCode = 1;
  }
}
