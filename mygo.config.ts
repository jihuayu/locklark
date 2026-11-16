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

const signingIdentity = process.env.PASSME_MACOS_SIGNING_IDENTITY || "-";
const entitlements = process.env.PASSME_MACOS_ENTITLEMENTS;
const provisioningProfile = process.env.PASSME_MACOS_PROVISIONING_PROFILE;
const notaryProfile = process.env.PASSME_NOTARY_PROFILE;

export default defineConfig({
  name: "Passme",
  slug: "passme",
  identifier: "app.passme.desktop",
  version: "0.1.0",
  copyright: "© 2026 Passme contributors",
  main: "./cmd/passme-desktop",
  out: "out",
  macos: {
    minimumSystemVersion: "13.0",
    signingIdentity,
    ...(entitlements ? { entitlements } : {}),
    ...(provisioningProfile ? { provisioningProfile } : {}),
    ...(notaryProfile ? { notarize: { keychainProfile: notaryProfile } } : {}),
  },
});
