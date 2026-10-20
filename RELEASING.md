# Releasing z0p

Tags are immutable. A release tag is a promise that the exact commit passed
the gates and that its recorded proof sizes and version metadata agree.

## Versioning

- `z0p` is pre-1.0; minor releases may change APIs, but wire-format changes
  always bump `codec::VERSION` and need explicit changelog notes.
- Bump `version` in `Cargo.toml` and `CITATION.cff`, and add a dated
  `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`.
- Never move or force-push a published tag. Fix forward with a patch release.
- A security fix gets a patch release and coordinated disclosure; do not put
  exploit details in a public release before reporters agree.

## Checklist

1. Start from a clean checkout of `main`; record the commit that will be
   tagged.
2. Bump the version in `Cargo.toml` and `CITATION.cff`; update
   `CHANGELOG.md` and the `[Unreleased]` comparison links.
3. Run the full gates:
   ```sh
   python3 tools/check.py
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
   python3 tools/release_check.py
   ```
4. Commit the release preparation and wait for CI to pass on that exact
   commit (stable, MSRV 1.74, rustdoc, and SIMD jobs).
5. Create an annotated tag and check the final metadata:
   ```sh
   git tag -a "v$VERSION" -m "z0p v$VERSION"
   python3 tools/release_check.py "v$VERSION"
   ```
6. Push the commit and tag only when authorized:
   ```sh
   git push origin main "v$VERSION"
   ```
7. Create the GitHub release, attach the paper, and verify the asset:
   ```sh
   gh release create "v$VERSION" --verify-tag --latest \
     --title "z0p v$VERSION" --notes-file /tmp/z0p-release.md \
     papers/z0p-eprint.pdf
   gh release view "v$VERSION" --json assets,url
   ```
8. Announce only after the release asset and CI status are verified.

## Release notes

Include:

- headline performance numbers from the pinned baseline, clearly marked as
  machine-dependent;
- breaking API or wire-format changes;
- security fixes with credit, if disclosure is complete;
- test/gate counts and any known limitations.

The `z0p-eprint.pdf` asset must be regenerated before tagging if the paper,
protocol, or benchmark claims changed. The PDF is committed; do not attach a
stale build.
