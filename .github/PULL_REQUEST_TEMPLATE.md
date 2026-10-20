## Summary

Describe the change and the problem it solves.

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test` and `cargo test --release` pass
- [ ] `python3 tools/check.py` passes (or the reason it was not run is stated)
- [ ] Public APIs remain fallible and documented
- [ ] No new dependencies and no `unsafe`
- [ ] Wire-format changes bump `codec::VERSION` and update size assertions
- [ ] Security-relevant changes update the relevant doc/test

## Security

If this fixes a vulnerability, do not include exploit details in the public
PR before coordinated disclosure. See [SECURITY.md](../SECURITY.md).
