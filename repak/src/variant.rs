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

/// How many leading bytes of a buffer get encrypted, and the buffer's length on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptionPlan {
    pub(crate) final_len: usize,
    pub(crate) encrypted_len: usize,
}

impl PakVariant {
    /// Decides how many leading bytes of a `data_len`-byte buffer get encrypted, and its length
    /// on disk. Write and read both call it with the entry's recorded compressed size, so they
    /// agree on where the ciphertext ends.
    ///
    /// An encrypted entry's data is stored padded to 16 bytes and the encrypted prefix is capped
    /// at that padded length, so a file shorter than its prefix is encrypted whole, as the game's
    /// own paks store it. An uncompressed entry records its unpadded size: readers read the
    /// aligned length of an encrypted entry anyway.
    pub(crate) fn encryption_plan(
        &self,
        mount_point: &str,
        path: &str,
        data_len: usize,
    ) -> EncryptionPlan {
        let prefix = self.raw_encrypted_prefix_len(mount_point, path);
        if prefix == 0 || data_len == 0 {
            return EncryptionPlan {
                final_len: data_len,
                encrypted_len: 0,
            };
        }
        let final_len = crate::data::pad_length(data_len, 16);
        EncryptionPlan {
            final_len,
            encrypted_len: prefix.min(final_len),
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
        aligned_len: usize,
    ) -> usize {
        match self {
            PakVariant::Standard => aligned_len,
            PakVariant::MarvelRivals => self
                .encryption_plan(mount_point, path, compressed_len)
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
        let plan = PakVariant::Standard.encryption_plan("../../../A/", "b.uasset", 12345);
        assert_eq!(plan.encrypted_len, 0);
        assert_eq!(plan.final_len, 12345);
        assert!(!PakVariant::Standard.reverse_word_order());
        assert!(PakVariant::Standard.index_trailer().is_empty());
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn test_marvel_rivals_large_file_encrypts_a_block_aligned_prefix_and_pads_to_16() {
        let plan = PakVariant::MarvelRivals.encryption_plan(
            "../../../MyGame/Content",
            "Foo/Bar.uasset",
            1_000_001,
        );
        assert_eq!(plan.final_len, 1_000_016);
        assert_eq!(
            plan.encrypted_len % 16,
            0,
            "prefix must be AES-block-aligned"
        );
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
                1_000_001,
            )
        );
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn test_marvel_rivals_small_file_is_padded_and_encrypted_whole() {
        // The game's own paks store a file shorter than its prefix this way
        for (len, padded) in [(10, 16), (14, 16), (61, 64)] {
            let plan = PakVariant::MarvelRivals.encryption_plan("../../../A/", "b.uasset", len);
            assert_eq!(
                plan,
                EncryptionPlan {
                    final_len: padded,
                    encrypted_len: padded
                },
                "{len}"
            );
        }
        let empty = PakVariant::MarvelRivals.encryption_plan("../../../A/", "b.uasset", 0);
        assert_eq!(
            empty,
            EncryptionPlan {
                final_len: 0,
                encrypted_len: 0
            }
        );
    }

    #[test]
    fn test_standard_read_encrypted_len_assumes_whole_buffer() {
        // Standard assumes an entry marked encrypted was fully encrypted, matching how a
        // real Unreal Engine pak encrypts a whole file - unrelated to whether *this* crate's
        // own writer ever proactively encrypts file data for the standard variant.
        assert_eq!(
            PakVariant::Standard.read_encrypted_len("../../../A/", "b.uasset", 100, 112),
            112
        );
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn test_marvel_rivals_read_encrypted_len_uses_the_recorded_unpadded_size() {
        // An uncompressed entry records 61 bytes; the reader reads 64 and decrypts all of them
        assert_eq!(
            PakVariant::MarvelRivals.read_encrypted_len("../../../A/", "b.uasset", 61, 64),
            64
        );
    }
}
