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
                            let start = offset;
                            offset += block.compressed_size as u64;
                            let end = offset;
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
        let PartialEntryData::Blocks { data: buf, .. } = &mut data else {
            unreachable!()
        };
        // V10+'s *encoded* index entries (see `Entry::write_encoded`) have no field for a
        // compressed size that differs from the uncompressed one at all when there's no
        // compression - the reader just assumes they're equal - so growing an uncompressed
        // entry via padding to fully encrypt a small file is only safe below V10, where
        // `Entry::write` always stores both sizes independently; `encryption_plan` floors to
        // a full-block boundary instead when it can't grow.
        let can_grow = compression.is_some() || version < Version::V10;
        let plan = ctx
            .variant
            .encryption_plan(ctx.mount_point, ctx.path, buf.len(), can_grow);
        if plan.final_len > buf.len() {
            buf.resize(plan.final_len, 0);
        }
        if plan.encrypted_len > 0 {
            encrypt(ctx.variant, key, &mut buf[..plan.encrypted_len]);
            encrypted = true;
        }
        compressed_size = buf.len() as u64;
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
