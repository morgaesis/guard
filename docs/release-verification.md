# Verifying release artifacts

Every release ships binary tarballs, per-target CycloneDX SBOMs
(`*.cdx.json`), and a `SHA256SUMS` manifest covering both. All of these
assets carry signed build provenance attestations recorded in GitHub's
attestation store.

## Checksums

Download the artifacts you need together with `SHA256SUMS` into one
directory, then verify integrity:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

`SHA256SUMS` lists every tarball and SBOM by basename with deterministic
ordering, so the file itself is byte-stable for a given release.

## Build provenance

Each tarball, each SBOM, and `SHA256SUMS` has a build provenance
attestation signed via GitHub's OIDC identity for the release workflow.
Verification proves the artifact was built by this repository's release
workflow from a specific commit, not modified after upload:

```sh
gh attestation verify guard-v1.2.3-x86_64-unknown-linux-gnu.tar.gz \
  --repo morgaesis/ssh-guard
```

The command exits non-zero if the artifact has no matching attestation or
its digest differs from the attested subject. The verified output includes
the source commit and the workflow that produced the artifact.

## SBOM

The SBOMs are CycloneDX JSON inventories of every crate compiled into the
released binary, one per target triple because the dependency set differs
between Unix and Windows builds (for example `libc` and `uzers` on Unix,
`windows-service` and `windows-sys` on Windows). Vendored native code is
included through its wrapping crate: the bundled SQLite comes in via
`rusqlite`/`libsqlite3-sys`, and the TLS stack via `ring` and `rustls`.

Use the SBOM to answer "is release X affected by CVE Y": feed it to a
scanner such as `grype sbom:guard-v1.2.3-x86_64-unknown-linux-gnu.cdx.json`
or query it directly:

```sh
jq -r '.components[] | "\(.name) \(.version)"' \
  guard-v1.2.3-x86_64-unknown-linux-gnu.cdx.json
```
