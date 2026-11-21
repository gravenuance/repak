# TODO

- [ ] **`Error::OodleUnavailable` changed shape.** It now carries the getter's reason (`OodleUnavailable(String)`), which breaks any `match` on the unit variant. Nothing in this workspace or retoc matches on it (checked 2026-11-19); bump the crate version with the next release of the fork.
- [ ] **Cross-target check of repak_bind.** `cargo check --target aarch64-unknown-linux-gnu -p repak_bind` was not run (target not installed; the x86_64 Linux target stops on zstd-sys needing a C cross-compiler). Run it in WSL or CI.
