// MyGo packaging and code-signing configuration for the native desktop app.
//
// Development builds stay ad hoc signed (`-`) and must not carry restricted
// keychain entitlements: an ad-hoc process with such entitlements is killed by
// the OS. Release builds set the environment variables below and use
// scripts/macos_release.sh, which also materializes the concrete Team ID in the
// entitlements plist. See macos/README.md.
//
// defineConfig is a local identity helper so evaluating this file needs only
// Bun or Node 22.18+, not an npm install of mygo-cli.

const defineConfig = <T,>(config: T): T => config;

const signingIdentity = process.env.LOCKLARK_MACOS_SIGNING_IDENTITY || "-";
const entitlements = process.env.LOCKLARK_MACOS_ENTITLEMENTS;
const provisioningProfile = process.env.LOCKLARK_MACOS_PROVISIONING_PROFILE;
const notaryProfile = process.env.LOCKLARK_NOTARY_PROFILE;

export default defineConfig({
  name: "Locklark",
  slug: "locklark",
  identifier: "app.locklark.desktop",
  version: "0.1.0",
  copyright: "© 2026 Locklark contributors",
  main: "./cmd/locklark-desktop",
  out: "out",
  macos: {
    minimumSystemVersion: "13.0",
    signingIdentity,
    ...(entitlements ? { entitlements } : {}),
    ...(provisioningProfile ? { provisioningProfile } : {}),
    ...(notaryProfile ? { notarize: { keychainProfile: notaryProfile } } : {}),
  },
});
