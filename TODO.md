# TODO

- [ ] **`RePak.Tests.TestWritePak` crashes the test host** with an AccessViolationException inside
  `RePakInterop.pak_reader_get` (called from `PakReader.Get`), reading back the pak the test has just written. It
  crashed the same way on net8.0 with the old `repak_bind.dll`, so it predates the net11.0 move (2026-11-19); the run
  needs `target/release/repak_bind.dll` copied beside the test DLL first, or both tests fail with DllNotFoundException.
  UAssetEditor ships this `repak_bind.dll`, so find out whether its own reads can hit the same fault. Done when the
  root cause is known and `dotnet test` in `repak_cs/` passes.
