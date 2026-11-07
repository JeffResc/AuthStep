# AuthStep

Self-service client certificates for your users' devices. People sign in with your identity provider (OIDC), and AuthStep issues mTLS client certificates through [step-ca](https://github.com/smallstep/certificates), which runs as an intermediate CA under your offline root.

- **Browsers** (Windows, Linux, Android, Firefox anywhere): the key is created in the browser and never leaves it. Users download a `.p12` (AES-256) or PEM files.
- **iPhone, iPad and Mac**: a signed configuration profile enrols the device over SCEP; the key is created on the device and cannot be exported.
- **Apple TV**: the same profile, fetched once through a short link that the user types on the TV.
- Users revoke their own certificates; admins revoke any, or all of a user's (offboarding). step-ca publishes the CRL.
- Per-user limits, an audit log, email notices and expiry reminders, install guides for each platform, and a QR code to set up another device.

## Install

The Helm chart and container image are published to GHCR:

```bash
helm install authstep oci://ghcr.io/jeffresc/charts/authstep -f values.yaml
```

The chart can also deploy step-ca for you (`step-certificates.enabled: true`). See the [operator guide](docs/operator-guide.md) for the step-ca configuration, Secrets, and a full values example, and [root-setup.md](docs/root-setup.md) for creating the root and intermediate CA. Chart values are listed in [charts/authstep/README.md](charts/authstep/README.md).

Binaries for Linux and macOS (amd64, arm64) are attached to each [GitHub release](https://github.com/JeffResc/AuthStep/releases), with SHA-256 checksums. The container image `ghcr.io/jeffresc/authstep` is built on distroless (`static-debian12:nonroot`) for `linux/amd64` and `linux/arm64`.

## Try it locally

```bash
hack/demo-k3d.sh up            # k3d cluster with AuthStep, step-ca, Dex and Mailpit (about a minute)
hack/demo-k3d.sh up --public   # the same, reachable from your phone through Cloudflare quick tunnels
hack/demo-k3d.sh down
```

Locally, open http://authstep.localhost:8081 ("In group" signs in as an admin; "No group" is refused) and http://mail.localhost:8081 for the emails. With `--public`, the script prints `https://*.trycloudflare.com` addresses instead; they are public while the demo runs, so tear it down when you are done. The demo does not change your kubectl context.

## Development

```bash
go test -race ./...
node --test internal/web/jstest/*.test.mjs
golangci-lint run ./...
```

For a local stack (Dex, step-ca, Mailpit), see the commands at the top of [dev/dex.yaml](dev/dex.yaml) and run `dev/step-ca-init.sh` once. [PLAN.md](PLAN.md) records the design decisions and how each part was verified.

Releases are cut by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/) on `main`.
