# repak_cs

C# bindings for repak: `RePak` wraps the native `repak_bind` library (the `repak_bind` crate), and `RePak.Tests` tests the wrapper against it. The bindings are by Truman Kilen.

## Running the tests

From the repository root:

```
cargo build -p repak_bind
dotnet test repak_cs/repak_cs.sln
```

For a Release run, build the library with `--release` and test with `-c Release`. The test project copies `repak_bind.dll` (`librepak_bind.so` or `.dylib` elsewhere) from `target/debug` or `target/release` into its output folder, and fails the build with that command if the file is missing.

Build the library with `-p repak_bind`, not `--workspace`: a workspace build also enables repak's `oodle` feature, which links a download path that `repak_bind` never calls and that only makes the DLL larger.

## Using the library

- `new PakBuilder()`, then `Key(...)`, `Compression(...)` and `Variant(PakVariant.MarvelRivals)` as needed. The default is the standard pak format, and a builder is consumed by `Reader` or `Writer`.
- Marvel Rivals paks need both the key and `PakVariant.MarvelRivals`.
- Oodle compressed entries are read through the DLL that the `REPAK_OODLE_DLL` environment variable names, an absolute path to an `oo2core_*_win64.dll`. Nothing else is searched and nothing is downloaded. If the variable is unset or the file does not load, reading such an entry fails with "pointer to OodleLZ_Decompress was not provided". The variable is read again on the next read after a failure and kept after a success.
