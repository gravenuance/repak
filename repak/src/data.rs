use std::io::Write;

use crate::{
    entry::{Block, Entry},
    variant::EncryptionContext,
    Compression, Error, Hash, PakVariant, Version, VersionMajor,
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn pad_length(length: usize, alignment: usize) -> usize {
    length + (alignment - length % alignment) % alignment
}

pub(crate) fn pad_zeros_to_alignment(v: &mut Vec<u8>, alignment: usize) {
    v.resize(pad_length(v.len(), alignment), 0);
}

/// AES over one 16-byte block, honouring the variant's word-order convention.
#[cfg(feature = "encryption")]
fn encrypt_block(variant: PakVariant, key: &aes::Aes256, chunk: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    if variant.reverse_word_order() {
        chunk.chunks_mut(4).for_each(|c| c.reverse());
    }
    key.encrypt_block(aes::Block::from_mut_slice(chunk));
    if variant.reverse_word_order() {
        chunk.chunks_mut(4).for_each(|c| c.reverse());
    }
}

#[cfg(feature = "encryption")]
pub(crate) fn encrypt(variant: PakVariant, key: &aes::Aes256, bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(16) {
        encrypt_block(variant, key, chunk);
    }
}

#[cfg(feature = "encryption")]
pub(crate) fn decrypt(
    variant: PakVariant,
    key: &super::Key,
    bytes: &mut [u8],
) -> Result<()> {
    if let super::Key::Some(key) = key {
        use aes::cipher::BlockDecrypt;
        let reverse = variant.reverse_word_order();
        for chunk in bytes.chunks_mut(16) {
            if reverse {
                chunk.chunks_mut(4).for_each(|c| c.reverse());
            }
            key.decrypt_block(aes::Block::from_mut_slice(chunk));
            if reverse {
                chunk.chunks_mut(4).for_each(|c| c.reverse());
            }
        }
        Ok(())
    } else {
        Err(super::Error::Encrypted)
    }
}

pub struct PartialEntry<D: AsRef<[u8]>> {
    compression: Option<Compression>,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_block_size: u32,
    data: PartialEntryData<D>,
    encrypted: bool,
    hash: Hash,
}
pub(crate) struct PartialBlock {
    uncompressed_size: usize,
    compressed_size: usize,
}
pub(crate) enum PartialEntryData<D> {
    Slice(D),
    /// `data` is the concatenation of every block's (possibly encrypted) bytes; `blocks`
    /// gives each block's boundary within it. Kept flat, rather than one `Vec<u8>` per
    /// block, so per-file encryption can be applied to the whole buffer in one pass after
    /// compression instead of block-by-block.
    Blocks {
        data: Vec<u8>,
        blocks: Vec<PartialBlock>,
    },
}
impl<D: AsRef<[u8]>> PartialEntryData<D> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            PartialEntryData::Slice(data) => data.as_ref(),
            PartialEntryData::Blocks { data, .. } => data,
        }
    }
}

#[cfg(feature = "compression")]
fn get_compression_slot(
    version: Version,
    compression_slots: &mut Vec<Option<Compression>>,
    compression: Compression,
) -> Result<u32> {
    let slot = compression_slots
        .iter()
        .enumerate()
        .find(|(_, s)| **s == Some(compression));
    Ok(if let Some((i, _)) = slot {
        // existing found
        i
    } else {
        if version.version_major() < VersionMajor::FNameBasedCompression {
            return Err(Error::Other(format!(
                "cannot use {compression:?} prior to FNameBasedCompression (pak version 8)"
            )));
        }

        // find empty slot
        if let Some((i, empty_slot)) = compression_slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.is_none())
        {
            // empty found, set it to used compression type
            *empty_slot = Some(compression);
            i
        } else {
            // no empty slot found, add a new one
            compression_slots.push(Some(compression));
            compression_slots.len() - 1
        }
    } as u32)
}

impl<D: AsRef<[u8]>> PartialEntry<D> {
    pub(crate) fn build_entry(
        &self,
        version: Version,
        #[allow(unused)] compression_slots: &mut Vec<Option<Compression>>,
        file_offset: u64,
    ) -> Result<Entry> {
        #[cfg(feature = "compression")]
        let compression_slot = self
            .compression
            .map(|c| get_compression_slot(version, compression_slots, c))
            .transpose()?;
        #[cfg(not(feature = "compression"))]
        let compression_slot = None;

        let blocks = match &self.data {
            PartialEntryData::Slice(_) => None,
            PartialEntryData::Blocks { blocks, .. } if blocks.is_empty() => None,
            PartialEntryData::Blocks { blocks, .. } => {
                let entry_size =
                    Entry::get_serialized_size(version, compression_slot, blocks.len() as u32);

                let mut offset = entry_size;
                if version.version_major() < VersionMajor::RelativeChunkOffsets {
                    offset += file_offset;
                };

                Some(
                    blocks
                        .iter()
                        .map(|block| {
                            // An encrypted entry's blocks are stored padded to 16 bytes while
                            // each block records its unpadded size.
                            let start = offset;
                            let end = start + block.compressed_size as u64;
                            offset += match self.encrypted {
                                true => pad_length(block.compressed_size, 16) as u64,
                                false => block.compressed_size as u64,
                            };
                            Block { start, end }
                        })
                        .collect(),
                )
            }
        };

        Ok(Entry {
            offset: file_offset,
            compressed: self.compressed_size,
            uncompressed: self.uncompressed_size,
            compression_slot,
            timestamp: None,
            hash: Some(self.hash),
            blocks,
            flags: self.encrypted as u8,
            compression_block_size: self.compression_block_size,
        })
    }
    pub(crate) fn write_data<S: Write>(&self, stream: &mut S) -> Result<()> {
        match &self.data {
            PartialEntryData::Slice(data) => {
                stream.write_all(data.as_ref())?;
            }
            PartialEntryData::Blocks { data, .. } => {
                stream.write_all(data)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn build_partial_entry<D>(
    allowed_compression: &[Compression],
    #[allow(unused)] ctx: EncryptionContext,
    #[allow(unused)] version: Version,
    data: D,
) -> Result<PartialEntry<D>>
where
    D: AsRef<[u8]>,
{
    // TODO hash needs to be post-compression/encryption
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();

    // Empty data cannot be compressed (would produce empty blocks causing decompression failures)
    let compression = if data.as_ref().is_empty() {
        None
    } else {
        // TODO possibly select best compression based on some criteria instead of picking first
        allowed_compression.first().cloned()
    };
    let uncompressed_size = data.as_ref().len() as u64;
    let compression_block_size;

    let (mut data, mut compressed_size) = match compression {
        #[cfg(not(feature = "compression"))]
        Some(_) => {
            unreachable!("should not be able to reach this point without compression feature")
        }
        #[cfg(feature = "compression")]
        Some(compression) => {
            // https://github.com/EpicGames/UnrealEngine/commit/3aad0ff7976be1073005dca2c1282af548b45d89
            // Block size must fit into flags field or it may cause unreadable paks for earlier Unreal Engine versions
            compression_block_size = 0x3e << 11; // max possible block size
            let mut concatenated = vec![];
            let mut blocks = vec![];
            for chunk in data.as_ref().chunks(compression_block_size as usize) {
                let compressed_chunk = compress(compression, chunk)?;
                hasher.update(&compressed_chunk);
                blocks.push(PartialBlock {
                    uncompressed_size: chunk.len(),
                    compressed_size: compressed_chunk.len(),
                });
                concatenated.extend_from_slice(&compressed_chunk);
            }
            let compressed_size = concatenated.len() as u64;

            (
                PartialEntryData::Blocks {
                    data: concatenated,
                    blocks,
                },
                compressed_size,
            )
        }
        None => {
            compression_block_size = 0;
            hasher.update(data.as_ref());
            (PartialEntryData::Slice(data), uncompressed_size)
        }
    };

    let mut encrypted = false;
    #[cfg(feature = "encryption")]
    if let super::Key::Some(key) = ctx.key {
        // Per-file encryption always needs an owned, mutable buffer - a `Slice` around the
        // caller's own data can't be mutated in place.
        if matches!(data, PartialEntryData::Slice(_)) {
            let PartialEntryData::Slice(inner) = data else {
                unreachable!()
            };
            data = PartialEntryData::Blocks {
                data: inner.as_ref().to_vec(),
                blocks: vec![],
            };
        }
        let PartialEntryData::Blocks { data: buf, blocks } = &mut data else {
            unreachable!()
        };
        let encrypts = ctx
            .variant
            .encryption_plan(ctx.mount_point, ctx.path, buf.len())
            .encrypted_len
            > 0;
        if encrypts {
            *buf = pad_blocks_for_encryption(buf, blocks);
            let plan = ctx
                .variant
                .encryption_plan(ctx.mount_point, ctx.path, buf.len());
            encrypt(ctx.variant, key, &mut buf[..plan.encrypted_len]);
            encrypted = true;
            // An uncompressed entry keeps its unpadded size, as the game's paks record it; the
            // padding sits on disk before the next entry.
            if compression.is_some() {
                compressed_size = buf.len() as u64;
            }
            // The game hashes the entry's recorded size of the bytes as stored
            hasher = Sha1::new();
            hasher.update(&buf[..compressed_size as usize]);
        }
    }

    Ok(PartialEntry {
        compression,
        compressed_size,
        uncompressed_size,
        compression_block_size,
        data,
        encrypted,
        hash: Hash(hasher.finalize().into()),
    })
}

/// Pads each compressed block (or an uncompressed buffer as a whole) to the AES block size,
/// as an encrypted entry is stored: the reader steps over each block's padded length. The
/// padding repeats the entry's first bytes, as the game's paks fill it.
#[cfg(feature = "encryption")]
fn pad_blocks_for_encryption(buf: &[u8], blocks: &[PartialBlock]) -> Vec<u8> {
    let sizes: Vec<usize> = if blocks.is_empty() {
        vec![buf.len()]
    } else {
        blocks.iter().map(|b| b.compressed_size).collect()
    };
    let filler = &buf[..sizes[0]];
    let mut padded = Vec::with_capacity(buf.len() + 15 * sizes.len());
    let mut pos = 0;
    for size in sizes {
        padded.extend_from_slice(&buf[pos..pos + size]);
        pos += size;
        let pad = pad_length(padded.len(), 16) - padded.len();
        padded.extend(filler.iter().cycle().take(pad));
    }
    padded
}

#[cfg(feature = "compression")]
fn compress(compression: Compression, data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let compressed = match compression {
        Compression::Zlib => {
            let mut compress =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Gzip => {
            let mut compress =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Zstd => zstd::stream::encode_all(data, 0)?,
        Compression::LZ4 => lz4_flex::block::compress(data),
        Compression::Oodle => {
            #[cfg(not(feature = "oodle"))]
            return Err(super::Error::Oodle);
            #[cfg(feature = "oodle")]
            {
                oodle_loader::oodle().unwrap().compress(
                    data.as_ref(),
                    oodle_loader::Compressor::Mermaid,
                    oodle_loader::CompressionLevel::Normal,
                )?
            }
        }
    };

    Ok(compressed)
}

#[cfg(all(test, feature = "compression", feature = "encryption"))]
mod test {
    use super::*;
    use aes::cipher::KeyInit;
    use sha1::{Digest, Sha1};

    const BLOCK: usize = 0x3e << 11;

    fn context(key: &super::super::Key) -> EncryptionContext<'_> {
        EncryptionContext {
            key,
            variant: PakVariant::MarvelRivals,
            mount_point: "../../../",
            path: "Marvel/Content/big.uasset",
        }
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state % 7) as u8
            })
            .collect()
    }

    fn zlib(chunk: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(chunk).unwrap();
        encoder.finish().unwrap()
    }

    /// The game's paks (pakchunk0, Patch_-Windows_1.1.3984769_P, pakchunkLocres) store every
    /// block of an encrypted compressed entry padded to 16 bytes, the padding a copy of the
    /// entry's first plaintext bytes; the index records each block's unpadded size, block
    /// starts advance by the padded size, the entry's compressed size is the padded total,
    /// and the hash covers the bytes as stored.
    #[test]
    fn marvel_rivals_pads_each_compressed_block_as_the_game_stores_it() {
        let data = noise(300_000);
        let key = super::super::Key::Some(aes::Aes256::new_from_slice(&[7; 32]).unwrap());
        let partial =
            build_partial_entry(&[Compression::Zlib], context(&key), Version::V11, &data[..])
                .unwrap();
        let entry = partial.build_entry(Version::V11, &mut vec![], 0).unwrap();
        let mut on_disk = vec![];
        partial.write_data(&mut on_disk).unwrap();

        let first_block = zlib(&data[..BLOCK]);
        let sizes: Vec<u64> = data.chunks(BLOCK).map(|c| zlib(c).len() as u64).collect();
        assert!(
            sizes.iter().any(|s| s % 16 != 0),
            "test needs an unaligned block"
        );
        let blocks = entry.blocks.as_ref().unwrap();
        assert_eq!(blocks.len(), sizes.len());
        let header = Entry::get_serialized_size(Version::V11, entry.compression_slot, 3);
        let mut start = header;
        for (i, (block, size)) in blocks.iter().zip(&sizes).enumerate() {
            assert_eq!(block.start, start, "block {i} start");
            assert_eq!(block.end - block.start, *size, "block {i} recorded size");
            let pad = ((16 - size % 16) % 16) as usize;
            let pad_at = (block.end - header) as usize;
            assert_eq!(
                &on_disk[pad_at..pad_at + pad],
                &first_block[..pad],
                "block {i} padding"
            );
            start += size + pad as u64;
        }
        assert_eq!(entry.compressed, start - header);
        assert_eq!(on_disk.len() as u64, entry.compressed);
        assert_eq!(
            entry.hash.unwrap().0,
            <[u8; 20]>::from(Sha1::digest(&on_disk))
        );
    }

    /// The game's uncompressed encrypted entries record the unpadded size, pad with a copy
    /// of the file's first bytes, and hash the recorded size of the bytes as stored.
    #[test]
    fn marvel_rivals_pads_an_uncompressed_entry_as_the_game_stores_it() {
        let data = noise(5000);
        let key = super::super::Key::Some(aes::Aes256::new_from_slice(&[7; 32]).unwrap());
        let partial = build_partial_entry(&[], context(&key), Version::V11, &data[..]).unwrap();
        let entry = partial.build_entry(Version::V11, &mut vec![], 0).unwrap();
        let mut on_disk = vec![];
        partial.write_data(&mut on_disk).unwrap();

        assert_eq!(entry.compressed, 5000);
        assert_eq!(on_disk.len(), 5008);
        // the encrypted prefix is at most 4096 bytes, so the tail is stored as plaintext
        assert_eq!(&on_disk[4096..5000], &data[4096..]);
        assert_eq!(&on_disk[5000..], &data[..8]);
        assert_eq!(
            entry.hash.unwrap().0,
            <[u8; 20]>::from(Sha1::digest(&on_disk[..5000]))
        );
    }
}
