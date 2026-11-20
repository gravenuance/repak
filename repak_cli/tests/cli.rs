use assert_cmd::cargo::cargo_bin_cmd;
use indoc::{formatdoc, indoc};

const PAK: &str = "../repak/tests/packs/pack_v11.pak";

#[test]
fn test_cli_info() {
    let assert = cargo_bin_cmd!("repak").arg("info").arg(PAK).assert();
    assert.success().stdout(indoc! {"
        mount point: ../mount/point/root/
        version: V11
        version major: Fnv64BugFix
        encrypted index: false
        encrytion guid: Some(00000000000000000000000000000000)
        compression: None
        path hash seed: Some(205C5A7D)
        4 file entries
    "});
}

#[test]
fn test_cli_list() {
    let assert = cargo_bin_cmd!("repak")
        .arg("list")
        .arg("-s")
        .arg("")
        .arg(PAK)
        .assert();
    assert.success().stdout(indoc! {r#"
        ../mount/point/root/directory/nested.txt
        ../mount/point/root/test.png
        ../mount/point/root/test.txt
        ../mount/point/root/zeros.bin
    "#});

    let assert = cargo_bin_cmd!("repak")
        .arg("list")
        .arg("-s")
        .arg("../mount")
        .arg(PAK)
        .assert();
    assert.success().stdout(indoc! {r#"
        point/root/directory/nested.txt
        point/root/test.png
        point/root/test.txt
        point/root/zeros.bin
    "#});

    let assert = cargo_bin_cmd!("repak")
        .arg("list")
        .arg("-s")
        .arg("../mount/root/asdf")
        .arg(PAK)
        .assert();
    assert.failure().stderr(indoc! {r#"
        Error: Prefix "../mount/root/asdf" does not match path "../mount/point/root/directory/nested.txt"
    "#});
}

#[test]
fn test_cli_get() {
    let assert = cargo_bin_cmd!("repak")
        .arg("get")
        .arg("-s")
        .arg("../mount/point")
        .arg(PAK)
        .arg("root/test.txt")
        .assert();
    assert.success().stdout(indoc! {r#"
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    "#});

    let assert = cargo_bin_cmd!("repak")
        .arg("get")
        .arg("-s")
        .arg("../mount/point")
        .arg(PAK)
        .arg("root/doesnotexist.txt")
        .assert();
    assert.failure().stderr(indoc! {r#"
        Error: No entry found at doesnotexist.txt
    "#});
}

#[test]
fn test_cli_pack() {
    let dir = tempfile::tempdir().unwrap();

    let out_pak = dir.path().join("output.pak");
    let out_dir = dir.path().join("output");

    let assert = cargo_bin_cmd!("repak")
        .arg("pack")
        .arg("../repak/tests/pack/")
        .arg("-m")
        .arg("../mount/point/root")
        .arg("--version")
        .arg("V11")
        .arg(&out_pak)
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Packed 4 files to {}
    "#, out_pak.to_string_lossy()});

    // TODO test packing to non-empty file

    let assert = cargo_bin_cmd!("repak")
        .arg("unpack")
        .arg(&out_pak)
        .arg("-s")
        .arg("../mount/point/root")
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Unpacked 4 files to {} from {}
    "#, out_dir.to_string_lossy(), out_pak.to_string_lossy()});
    assert!(!dir_diff::is_different("../repak/tests/pack/", out_dir).unwrap());
}

#[test]
fn test_cli_unpack() {
    let dir = tempfile::tempdir().unwrap();

    let assert = cargo_bin_cmd!("repak")
        .arg("unpack")
        .arg(PAK)
        .arg("-s")
        .arg("../mount")
        .arg("-o")
        .arg(dir.path())
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Unpacked 4 files to {} from ../repak/tests/packs/pack_v11.pak
    "#, &dir.path().to_string_lossy()});
    assert!(!dir_diff::is_different("../repak/tests/pack/", dir.path().join("point")).unwrap());

    // TODO test unpacking to non-empty directory
}

#[test]
fn test_cli_unpack_include() {
    let dir = tempfile::tempdir().unwrap();

    let assert = cargo_bin_cmd!("repak")
        .arg("unpack")
        .arg(PAK)
        .arg("-s")
        .arg("../mount")
        .arg("-i")
        .arg("point/**/*.txt")
        .arg("-o")
        .arg(dir.path())
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Unpacked 2 files to {} from ../repak/tests/packs/pack_v11.pak
    "#, &dir.path().to_string_lossy()});
}

#[test]
fn test_cli_hashlist() {
    let assert = cargo_bin_cmd!("repak")
        .arg("hash-list")
        .arg(PAK)
        .arg("-s")
        .arg("../mount")
        .assert();
    assert.success().stdout(formatdoc! {r#"
        246c88de650fb20d63abaeb7c1bd8556d0ea260bf4579beafe0b2597e00270a5 point/root/directory/nested.txt
        d7d3e1c21a5b98621add61a4244a413abf5ad6413b0d25ba09bfd5536c75e3b1 point/root/test.png
        56293a80e0394d252e995f2debccea8223e4b5b2b150bee212729b3b39ac4d46 point/root/test.txt
        e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad point/root/zeros.bin
    "#});
}

/// The game key as typed (and as IoStore uses it), and the key a Marvel Rivals pak is encrypted with: every 4-byte word reversed.
const RIVALS_PROFILE_KEY: &str = "0C263D8C22DCB085894899C3A3796383E9BF9DE0CBFB08C9BF2DEF2E84F29D74";
const RIVALS_PAK_KEY: &str = "8C3D260C85B0DC22C3994889836379A3E09DBFE9C908FBCB2EEF2DBF749DF284";
const RIVALS_CONTENT: &[u8] = b"marvel rivals entry contents";

fn cipher(key_hex: &str) -> aes::Aes256 {
    use aes::cipher::KeyInit;
    aes::Aes256::new_from_slice(&hex::decode(key_hex).unwrap()).unwrap()
}

/// Writes a one-entry V11 pak with the given cipher key and variant, as a plain repak user would.
fn write_pak(path: &std::path::Path, key_hex: &str, variant: repak::PakVariant) {
    let file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut writer = repak::PakBuilder::new()
        .key(cipher(key_hex))
        .variant(variant)
        .writer(file, repak::Version::V11, "../../../".to_string(), Some(0));
    writer
        .write_file("Marvel/Content/Foo.uasset", false, RIVALS_CONTENT)
        .unwrap();
    writer.write_index().unwrap();
}

#[test]
fn test_cli_marvel_rivals_takes_the_profile_key() {
    let dir = tempfile::tempdir().unwrap();
    let pak = dir.path().join("rivals.pak");
    write_pak(&pak, RIVALS_PAK_KEY, repak::PakVariant::MarvelRivals);

    let assert = cargo_bin_cmd!("repak")
        .args([
            "--variant",
            "marvel-rivals",
            "--aes-key",
            RIVALS_PROFILE_KEY,
        ])
        .args(["list", "-s", ""])
        .arg(&pak)
        .assert();
    assert
        .success()
        .stdout("../../../Marvel/Content/Foo.uasset\n");

    let assert = cargo_bin_cmd!("repak")
        .args([
            "--variant",
            "marvel-rivals",
            "--aes-key",
            &format!("0x{RIVALS_PROFILE_KEY}"),
        ])
        .args(["get", "-s", "../../../"])
        .arg(&pak)
        .arg("Marvel/Content/Foo.uasset")
        .assert();
    assert.success().stdout(RIVALS_CONTENT);
}

#[test]
fn test_cli_marvel_rivals_pack_is_encrypted_with_the_reversed_key() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir_all(input.join("Marvel/Content")).unwrap();
    std::fs::write(input.join("Marvel/Content/Foo.uasset"), RIVALS_CONTENT).unwrap();
    let pak = dir.path().join("packed.pak");

    cargo_bin_cmd!("repak")
        .args([
            "--variant",
            "marvel-rivals",
            "--aes-key",
            RIVALS_PROFILE_KEY,
        ])
        .args(["pack", "-q", "--version", "V11"])
        .arg(&input)
        .arg(&pak)
        .assert()
        .success();

    let mut file = std::fs::File::open(&pak).unwrap();
    let reader = repak::PakBuilder::new()
        .key(cipher(RIVALS_PAK_KEY))
        .variant(repak::PakVariant::MarvelRivals)
        .reader(&mut file)
        .unwrap();
    assert_eq!(
        reader.get("Marvel/Content/Foo.uasset", &mut file).unwrap(),
        RIVALS_CONTENT
    );
}

#[test]
fn test_cli_standard_variant_uses_the_key_as_given() {
    let dir = tempfile::tempdir().unwrap();
    let pak = dir.path().join("standard.pak");
    write_pak(&pak, RIVALS_PROFILE_KEY, repak::PakVariant::Standard);

    let assert = cargo_bin_cmd!("repak")
        .args(["--aes-key", RIVALS_PROFILE_KEY])
        .args(["get", "-s", "../../../"])
        .arg(&pak)
        .arg("Marvel/Content/Foo.uasset")
        .assert();
    assert.success().stdout(RIVALS_CONTENT);
}
