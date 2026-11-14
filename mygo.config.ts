// MyGo packaging, release and code-signing configuration for the native
// desktop app.
//
// Development builds stay ad hoc signed (`-`) and must not carry restricted
// keychain entitlements: an ad-hoc process with such entitlements is killed by
// the OS. Release builds set the environment variables below and use
// scripts/macos_release.sh and .github/workflows/desktop-release.yml. See
// macos/README.md and docs/release.md.
//
// defineConfig is a local identity helper so evaluating this file needs only
// Bun or Node 22.18+, not an npm install of mygo-cli.

const defineConfig = <T,>(config: T): T => config;

const version =
  process.env.LOCKLARK_VERSION?.trim().replace(/^v/, "") || "0.1.0";
const signingIdentity = process.env.LOCKLARK_MACOS_SIGNING_IDENTITY || "-";
const entitlements = process.env.LOCKLARK_MACOS_ENTITLEMENTS;
const provisioningProfile = process.env.LOCKLARK_MACOS_PROVISIONING_PROFILE;
const notaryProfile = process.env.LOCKLARK_NOTARY_PROFILE;
const notaryKeychain = process.env.NOTARY_KEYCHAIN;
const windowsCertificate = process.env.LOCKLARK_WINDOWS_CERTIFICATE_FILE;
const windowsSignCommand = process.env.LOCKLARK_WINDOWS_SIGN_COMMAND;

export default defineConfig({
  name: "Locklark",
  slug: "locklark",
  identifier: "app.locklark.desktop",
  version,
  copyright: "© 2026 Locklark contributors",
  main: "./cmd/locklark-desktop",
  out: "out",
  windows: {
    displayName: "Locklark",
    installDirName: "Locklark",
    ...(windowsSignCommand
      ? { signCommand: windowsSignCommand }
      : windowsCertificate
        ? { certificate: windowsCertificate }
        : {}),
  },
  macos: {
    minimumSystemVersion: "13.0",
    signingIdentity,
    ...(entitlements ? { entitlements } : {}),
    ...(provisioningProfile ? { provisioningProfile } : {}),
    ...(notaryProfile
      ? {
          notarize: {
            keychainProfile: notaryProfile,
            ...(notaryKeychain ? { keychain: notaryKeychain } : {}),
          },
        }
      : {}),
  },
  updates: {
    publicKey: "yQcW8xlw7T2aQPOeiAzRuzH1LTkMyW+WDsI1PVD1w98=",
    github: "jihuayu/locklark",
  },
});
