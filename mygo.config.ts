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
  process.env.PASSME_VERSION?.trim().replace(/^v/, "") || "0.1.0";
const signingIdentity = process.env.PASSME_MACOS_SIGNING_IDENTITY || "-";
const entitlements = process.env.PASSME_MACOS_ENTITLEMENTS;
const provisioningProfile = process.env.PASSME_MACOS_PROVISIONING_PROFILE;
const notaryProfile = process.env.PASSME_NOTARY_PROFILE;
const notaryKeychain = process.env.NOTARY_KEYCHAIN;
const windowsCertificate = process.env.PASSME_WINDOWS_CERTIFICATE_FILE;
const windowsSignCommand = process.env.PASSME_WINDOWS_SIGN_COMMAND;

export default defineConfig({
  name: "Passme",
  slug: "passme",
  identifier: "app.passme.desktop",
  version,
  copyright: "© 2026 Passme contributors",
  main: "./cmd/passme-desktop",
  out: "out",
  windows: {
    displayName: "Passme",
    installDirName: "Passme",
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
    github: "jihuayu/passme",
  },
});
