/// Selects deviations from the standard Unreal Engine pak format that some games apply.
/// `Standard` never changes any behaviour compared to a key-value `PakBuilder` without a
/// variant at all; picking a specific game's variant opts into *only* that game's known
/// quirks, so generic pak handling is unaffected unless a caller explicitly asks for it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PakVariant {
    #[default]
    Standard,
    /// Marvel Rivals: a hash-derived prefix of each file's (post-compression) data is
    /// encrypted rather than the whole file, AES operates on each 16-byte block with its
    /// four 4-byte words byte-reversed before and after the cipher, and a fixed trailer is
    /// written between the index and the footer.
    MarvelRivals,
}

/// Everything needed to decide how a specific file's data gets encrypted or decrypted:
/// whether a key is even available, which variant's rules apply, and the file's own identity
/// (needed by variants whose encrypted-prefix length is derived from the path). Bundled into
/// one struct so `Entry::write_file`/`read_file` don't have to take each of these separately.
#[derive(Clone, Copy)]
pub(crate) struct EncryptionContext<'a> {
    pub(crate) key: &'a super::Key,
    pub(crate) variant: PakVariant,
    pub(crate) mount_point: &'a str,
    pub(crate) path: &'a str,
}

/// The fixed byte sequence Marvel Rivals writes between the end of the full directory index
/// and the start of the footer. Purpose unconfirmed; present unconditionally whenever this
/// variant is selected, independent of whether the index itself ends up encrypted.
const MARVEL_RIVALS_INDEX_TRAILER: [u8; 35] = [
    0x06, 0x12, 0x24, 0x20, 0x06, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Salt mixed into the path hash ahead of the lowercased path itself.
const MARVEL_RIVALS_ENCRYPT_LIMIT_SALT: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

/// How many leading bytes of a buffer get encrypted, and what the buffer's final length ends
/// up being. `final_len` only ever differs from the buffer's starting length when `can_grow`
/// is true and padding was needed - see `PakVariant::encryption_plan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptionPlan {
    pub(crate) final_len: usize,
    pub(crate) encrypted_len: usize,
}

impl PakVariant {
    /// Decides how many leading bytes of a `data_len`-byte buffer get encrypted, and whether
    /// the buffer needs to grow first to hold that encryption.
    ///
    /// Write and read call this with the same two questions answered the same way -
    /// `data_len` (the buffer's length *before* writing, or the entry's recorded compressed
    /// size when reading it back - the two are identical unless growth happened) and
    /// `can_grow` (whether the entry is compressed, so its on-disk size is already stored
    /// independently of its uncompressed size) - which is what keeps them from disagreeing
    /// about where the ciphertext ends. An *un*compressed entry's encoded index has no field
    /// for a compressed size that differs from the uncompressed one at all (the reader just
    /// assumes they're equal), so growing such a buffer via padding would silently corrupt
    /// the round trip; the encrypted region is floored to the nearest full AES block instead,
    /// leaving a short remainder as plaintext (or nothing encrypted at all, for a file under
    /// 16 bytes).
    pub(crate) fn encryption_plan(
        &self,
        mount_point: &str,
        path: &str,
        data_len: usize,
        can_grow: bool,
    ) -> EncryptionPlan {
        let requested = self
            .raw_encrypted_prefix_len(mount_point, path)
            .min(data_len);
        if requested == 0 || requested < data_len {
            EncryptionPlan {
                final_len: data_len,
                encrypted_len: requested,
            }
        } else if can_grow {
            let final_len = crate::data::pad_length(data_len, 16);
            EncryptionPlan {
                final_len,
                encrypted_len: final_len,
            }
        } else {
            EncryptionPlan {
                final_len: data_len,
                encrypted_len: data_len - (data_len % 16),
            }
        }
    }

    /// The variant's raw, hash-derived encrypted-prefix length, uncapped by any particular
    /// file's length. `Standard` returns 0 - per-file data is never proactively encrypted by
    /// this crate's own writer for the generic case (only index encryption, controlled
    /// separately by whether a key is configured, applies); a caller that wants generic
    /// full-file encryption isn't served by this - only a variant that asks for it.
    fn raw_encrypted_prefix_len(&self, mount_point: &str, path: &str) -> usize {
        match self {
            PakVariant::Standard => 0,
            #[cfg(feature = "encryption")]
            PakVariant::MarvelRivals => marvel_rivals_encrypted_prefix_len(mount_point, path),
            #[cfg(not(feature = "encryption"))]
            PakVariant::MarvelRivals => 0,
        }
    }

    /// How many of the bytes just read for an entry already marked encrypted are actually
    /// ciphertext. `Standard` assumes the whole (alignment-padded) buffer, matching how a
    /// real, externally-produced Unreal Engine pak encrypts a full file; a variant that only
    /// encrypts a hash-derived prefix on write overrides this to match, via the same
    /// `encryption_plan` the write side used.
    pub(crate) fn read_encrypted_len(
        &self,
        mount_point: &str,
        path: &str,
        compressed_len: usize,
        can_grow: bool,
        aligned_len: usize,
    ) -> usize {
        match self {
            PakVariant::Standard => aligned_len,
            PakVariant::MarvelRivals => self
                .encryption_plan(mount_point, path, compressed_len, can_grow)
                .encrypted_len
                .min(aligned_len),
        }
    }

    /// Whether AES should operate on each block with its four 4-byte words reversed
    /// before and after the cipher, instead of the block's raw byte order. Applies to both
    /// index encryption and per-file encryption.
    pub(crate) fn reverse_word_order(&self) -> bool {
        matches!(self, PakVariant::MarvelRivals)
    }

    /// Extra bytes written after the full directory index and before the footer. Empty for
    /// every variant except the ones that need it.
    pub(crate) fn index_trailer(&self) -> &'static [u8] {
        match self {
            PakVariant::Standard => &[],
            PakVariant::MarvelRivals => &MARVEL_RIVALS_INDEX_TRAILER,
        }
    }
}

#[cfg(feature = "encryption")]
fn marvel_rivals_encrypted_prefix_len(mount_point: &str, path: &str) -> usize {
    let full_path = join_mount_path(mount_point, path);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&MARVEL_RIVALS_ENCRYPT_LIMIT_SALT);
    hasher.update(full_path.to_lowercase().as_bytes());
    let seed = u64::from_le_bytes(hasher.finalize().as_bytes()[0..8].try_into().unwrap());
    // Rounds down to a multiple of 64 (so always AES-block-aligned), 256..=4096 after
    // rounding - the formula never actually produces 0, but the fallback below is kept to
    // match the reference implementation this was ported from exactly.
    let limit = ((seed % 0x3D) * 63 + 319) & !0x3F;
    if limit == 0 {
        0x1000
    } else {
        limit as usize
    }
}

/// Joins a mount point and an entry path the way the game hashes it: collapse doubled
/// slashes, then drop a leading "../../../" if present (repak's own default pack mount
/// point). A mount point that doesn't start with that prefix is left as-is rather than
/// panicking - this only matters for the `MarvelRivals` variant, and an unexpected mount
/// point there means the hash (and therefore which bytes get encrypted) won't match what the
/// game expects, not that anything crashes.
fn join_mount_path(mount_point: &str, path: &str) -> String {
    let joined = format!("{mount_point}/{path}");
    let mut last_was_slash = false;
    let collapsed: String = joined
        .chars()
        .filter(|&c| {
            let keep = c != '/' || !last_was_slash;
            last_was_slash = c == '/';
            keep
        })
        .collect();
    collapsed
        .strip_prefix("../../../")
        .unwrap_or(&collapsed)
        .to_string()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_join_mount_path() {
        assert_eq!(
            join_mount_path("../../../MyGame/Content", "Foo/Bar.uasset"),
            "MyGame/Content/Foo/Bar.uasset"
        );
        // doubled slash between mount point and path is collapsed
        assert_eq!(
            join_mount_path("../../../MyGame/Content/", "Foo/Bar.uasset"),
            "MyGame/Content/Foo/Bar.uasset"
        );
        // an unrecognized mount point convention is left alone instead of panicking
        assert_eq!(join_mount_path("/Game/", "Foo.uasset"), "/Game/Foo.uasset");
    }

    #[test]
    fn test_standard_variant_never_encrypts_file_data() {
        let plan = PakVariant::Standard.encryption_plan("../../../A/", "b.uasset", 12345, true);
        assert_eq!(plan.encrypted_len, 0);
        assert_eq!(plan.final_len, 12345);
        assert!(!PakVariant::Standard.reverse_word_order());
        assert!(PakVariant::Standard.index_trailer().is_empty());
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn test_marvel_rivals_large_compressed_file_encrypts_a_block_aligned_prefix_without_growing() {
        let plan = PakVariant::MarvelRivals.encryption_plan(
            "../../../MyGame/Content",
            "Foo/Bar.uasset",
            1_000_000,
            true,
        );
        assert_eq!(plan.final_len, 1_000_000, "a large file is never padded");
        assert_eq!(plan.encrypted_len % 16, 0, "prefix must be AES-block-aligned");
        // ((seed % 0x3D) * 63 + 319) ranges 319..=4099 before rounding down to a multiple of
        // 64, giving 256..=4096.
        assert!(
            (256..=4096).contains(&plan.encrypted_len),
            "len was {}",
            plan.encrypted_len
        );
        // deterministic: same inputs, same result
        assert_eq!(
            plan,
            PakVariant::MarvelRivals.encryption_plan(
                "../../../MyGame/Content",
                "Foo/Bar.uasset",
                1_000_000,
                true,
            )
        );
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn test_marvel_rivals_small_compressed_file_is_padded_and_fully_encrypted() {
        // A compressed entry's compressed size is already independent of its uncompressed
        // size in the format, so padding to grow it is safe.
        let plan = PakVariant::MarvelRivals.encryption_plan("../../../A/", "b.uasset", 10, true);
        assert_eq!(plan.final_len % 16, 0);
        assert!(plan.final_len >= 10);
        assert_eq!(plan.encrypted_len, plan.final_len, "the whole padded file is encrypted");
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn test_marvel_rivals_small_uncompressed_file_is_never_padded() {
        // An uncompressed entry has no way to record a compressed size that differs from its
        // uncompressed size, so growth is not allowed - the buffer's length must come back
        // out unchanged even though the file is smaller than the hash-derived limit.
        let plan = PakVariant::MarvelRivals.encryption_plan("../../../A/", "b.uasset", 10, false);
        assert_eq!(plan.final_len, 10, "an uncompressed entry must never grow");
        assert_eq!(plan.encrypted_len, 0, "10 bytes is under one AES block");

        let plan14 = PakVariant::MarvelRivals.encryption_plan("../../../A/", "b.uasset", 14, false);
        assert_eq!(plan14.final_len, 14);
        assert_eq!(plan14.encrypted_len, 0, "14 bytes is still under one AES block");
    }

    #[test]
    fn test_standard_read_encrypted_len_assumes_whole_buffer() {
        // Standard assumes an entry marked encrypted was fully encrypted, matching how a
        // real Unreal Engine pak encrypts a whole file - unrelated to whether *this* crate's
        // own writer ever proactively encrypts file data for the standard variant.
        assert_eq!(
            PakVariant::Standard.read_encrypted_len("../../../A/", "b.uasset", 100, true, 112),
            112
        );
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn test_marvel_rivals_read_encrypted_len_matches_write_side_when_uncompressed_and_unchanged() {
        // Reading back with the exact same (unchanged, since uncompressed never grows) length
        // written must reproduce the same encrypted-byte count.
        let write_plan =
            PakVariant::MarvelRivals.encryption_plan("../../../A/", "b.uasset", 1_000_000, false);
        assert_eq!(
            PakVariant::MarvelRivals.read_encrypted_len(
                "../../../A/",
                "b.uasset",
                write_plan.final_len,
                false,
                write_plan.final_len,
            ),
            write_plan.encrypted_len
        );
    }
}
