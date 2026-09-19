use crate::Error;

use super::{ext::BoolExt, ext::ReadExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum EntryLocation {
    Data,
    Index,
}

#[derive(Debug)]
pub(crate) struct Block {
    pub start: u64,
    pub end: u64,
}

impl Block {
    pub fn read<R: io::Read>(reader: &mut R) -> Result<Self, super::Error> {
        Ok(Self {
            start: reader.read_u64::<LE>()?,
            end: reader.read_u64::<LE>()?,
        })
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        writer.write_u64::<LE>(self.start)?;
        writer.write_u64::<LE>(self.end)?;
        Ok(())
    }
}

// The zstd frame decoder (used for every other pak) requires a standard frame
// magic/descriptor. Some licensee pak variants instead store raw/headerless Zstd
// blocks - ZSTD_compressBlock's output - which only the deprecated "block API" can
// read back, and that API requires ZSTD_decompressBegin() to initialize context state
// before ZSTD_decompressBlock() will work (zstd-safe doesn't wrap either function, so
// this drops to the raw zstd-sys FFI directly). Returns the number of bytes written to
// `dst`, or Err(()) on any zstd-reported error.
#[cfg(feature = "compression")]
fn decompress_raw_zstd_block(dst: &mut [u8], src: &[u8]) -> Result<usize, ()> {
    unsafe {
        let dctx = zstd_sys::ZSTD_createDCtx();
        if dctx.is_null() {
            return Err(());
        }
        let result = (|| {
            if zstd_sys::ZSTD_isError(zstd_sys::ZSTD_decompressBegin(dctx)) != 0 {
                return Err(());
            }
            let written = zstd_sys::ZSTD_decompressBlock(
                dctx,
                dst.as_mut_ptr() as *mut core::ffi::c_void,
                dst.len(),
                src.as_ptr() as *const core::ffi::c_void,
                src.len(),
            );
            if zstd_sys::ZSTD_isError(written) != 0 {
                return Err(());
            }
            Ok(written)
        })();
        zstd_sys::ZSTD_freeDCtx(dctx);
        result
    }
}

fn align(offset: u64) -> u64 {
    // add alignment (aes block size: 16) then zero out alignment bits
    (offset + 15) & !15
}

fn compression_index_size(version: Version) -> CompressionIndexSize {
    match version {
        Version::V8A => CompressionIndexSize::U8,
        _ => CompressionIndexSize::U32,
    }
}

enum CompressionIndexSize {
    U8,
    U32,
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression_slot: Option<u32>,
    pub timestamp: Option<u64>,
    pub hash: Option<[u8; 20]>,
    pub blocks: Option<Vec<Block>>,
    pub flags: u8,
    pub compression_block_size: u32,
}

impl Entry {
    pub fn is_encrypted(&self) -> bool {
        0 != (self.flags & 1)
    }
    pub fn is_deleted(&self) -> bool {
        0 != (self.flags >> 1) & 1
    }
    pub fn get_serialized_size(
        version: super::Version,
        compression: Option<u32>,
        block_count: u32,
    ) -> u64 {
        let mut size = 0;
        size += 8; // offset
        size += 8; // compressed
        size += 8; // uncompressed
        size += match compression_index_size(version) {
            CompressionIndexSize::U8 => 1,  // 8 bit compression
            CompressionIndexSize::U32 => 4, // 32 bit compression
        };
        size += match version.version_major() == VersionMajor::Initial {
            true => 8, // timestamp
            false => 0,
        };
        size += 20; // hash
        size += match compression {
            Some(_) => 4 + (8 + 8) * block_count as u64, // blocks
            None => 0,
        };
        size += 1; // encrypted
        size += match version.version_major() >= VersionMajor::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }

    pub(crate) fn write_file<W: io::Write + io::Seek>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        allowed_compression: &[Compression],
        data: impl AsRef<[u8]>,
    ) -> Result<Self, super::Error> {
        // TODO hash needs to be post-compression
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&data);

        let offset = writer.stream_position()?;
        let len = data.as_ref().len() as u64;

        // TODO possibly select best compression based on some criteria instead of picking first
        let compression = allowed_compression.first().cloned();

        let compression_slot = if let Some(compression) = compression {
            // find existing
            let slot = compression_slots
                .iter()
                .enumerate()
                .find(|(_, s)| **s == Some(compression));
            Some(if let Some((i, _)) = slot {
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
        } else {
            None
        };

        let (blocks, compressed) = match compression {
            #[cfg(not(feature = "compression"))]
            Some(_) => {
                unreachable!("should not be able to reach this point without compression feature")
            }
            #[cfg(feature = "compression")]
            Some(compression) => {
                use std::io::Write;

                let entry_size = Entry::get_serialized_size(version, compression_slot, 1);
                let data_offset = offset + entry_size;

                let compressed = match compression {
                    Compression::Zlib => {
                        let mut compress = flate2::write::ZlibEncoder::new(
                            Vec::new(),
                            flate2::Compression::fast(),
                        );
                        compress.write_all(data.as_ref())?;
                        compress.finish()?
                    }
                    Compression::Gzip => {
                        let mut compress =
                            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                        compress.write_all(data.as_ref())?;
                        compress.finish()?
                    }
                    Compression::Zstd => zstd::stream::encode_all(data.as_ref(), 0)?,
                    Compression::Oodle => {
                        return Err(Error::Other("writing Oodle compression unsupported".into()))
                    }
                    // This backport only needed LZ4 *decoding* (to test a real-world legacy
                    // pak entry that turned out to use it) - writing new LZ4-compressed
                    // entries was never a goal here, so left unimplemented like Oodle above
                    // rather than guessing at an encoder API this crate doesn't otherwise use.
                    Compression::LZ4 => {
                        return Err(Error::Other("writing LZ4 compression unsupported".into()))
                    }
                };

                let compute_offset = |index: usize| -> u64 {
                    match version.version_major() >= VersionMajor::RelativeChunkOffsets {
                        true => index as u64 + (data_offset - offset),
                        false => index as u64 + data_offset,
                    }
                };

                let blocks = vec![Block {
                    start: compute_offset(0),
                    end: compute_offset(compressed.len()),
                }];

                (Some(blocks), Some(compressed))
            }
            None => (None, None),
        };

        let entry = super::entry::Entry {
            offset,
            compressed: compressed
                .as_ref()
                .map(|c: &Vec<u8>| c.len() as u64)
                .unwrap_or(len),
            uncompressed: len,
            compression_slot,
            timestamp: None,
            hash: Some(hasher.finalize().into()),
            blocks,
            flags: 0,
            compression_block_size: compressed.as_ref().map(|_| len as u32).unwrap_or_default(),
        };

        entry.write(writer, version, EntryLocation::Data)?;

        if let Some(compressed) = compressed {
            writer.write_all(&compressed)?;
        } else {
            writer.write_all(data.as_ref())?;
        }

        Ok(entry)
    }

    pub fn read<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let ver = version.version_major();
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression = match match compression_index_size(version) {
            CompressionIndexSize::U8 => reader.read_u8()? as u32,
            CompressionIndexSize::U32 => reader.read_u32::<LE>()?,
        } {
            0 => None,
            n => Some(n - 1),
        };
        let timestamp = (ver == VersionMajor::Initial).then_try(|| reader.read_u64::<LE>())?;
        let hash = Some(reader.read_guid()?);
        let blocks = (ver >= VersionMajor::CompressionEncryption && compression.is_some())
            .then_try(|| reader.read_array(Block::read))?;
        let flags = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u8())?
            .unwrap_or(0);
        let compression_block_size = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u32::<LE>())?
            .unwrap_or(0);
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression_slot: compression,
            timestamp,
            hash,
            blocks,
            flags,
            compression_block_size,
        })
    }

    pub fn write<W: io::Write>(
        &self,
        writer: &mut W,
        version: super::Version,
        location: EntryLocation,
    ) -> Result<(), super::Error> {
        writer.write_u64::<LE>(match location {
            EntryLocation::Data => 0,
            EntryLocation::Index => self.offset,
        })?;
        writer.write_u64::<LE>(self.compressed)?;
        writer.write_u64::<LE>(self.uncompressed)?;
        let compression = self.compression_slot.map_or(0, |n| n + 1);
        match compression_index_size(version) {
            CompressionIndexSize::U8 => writer.write_u8(compression.try_into().unwrap())?,
            CompressionIndexSize::U32 => writer.write_u32::<LE>(compression)?,
        }

        if version.version_major() == VersionMajor::Initial {
            writer.write_u64::<LE>(self.timestamp.unwrap_or_default())?;
        }
        if let Some(hash) = self.hash {
            writer.write_all(&hash)?;
        } else {
            panic!("hash missing");
        }
        if version.version_major() >= VersionMajor::CompressionEncryption {
            if let Some(blocks) = &self.blocks {
                writer.write_u32::<LE>(blocks.len() as u32)?;
                for block in blocks {
                    block.write(writer)?;
                }
            }
            writer.write_u8(self.flags)?;
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        Ok(())
    }

    pub fn read_encoded<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let bits = reader.read_u32::<LE>()?;
        let compression = match (bits >> 23) & 0x3f {
            0 => None,
            n => Some(n - 1),
        };

        let encrypted = (bits & (1 << 22)) != 0;
        let compression_block_count: u32 = (bits >> 6) & 0xffff;
        let mut compression_block_size = bits & 0x3f;

        if compression_block_size == 0x3f {
            compression_block_size = reader.read_u32::<LE>()?;
        } else {
            compression_block_size <<= 11;
        }

        let mut var_int = |bit: u32| -> Result<_, super::Error> {
            Ok(if (bits & (1 << bit)) != 0 {
                reader.read_u32::<LE>()? as u64
            } else {
                reader.read_u64::<LE>()?
            })
        };

        let offset = var_int(31)?;
        let uncompressed = var_int(30)?;
        let compressed = match compression {
            None => uncompressed,
            _ => var_int(29)?,
        };

        let offset_base = Entry::get_serialized_size(version, compression, compression_block_count);

        let blocks = if compression_block_count == 1 && !encrypted {
            Some(vec![Block {
                start: offset_base,
                end: offset_base + compressed,
            }])
        } else if compression_block_count > 0 {
            let mut index = offset_base;
            Some(
                (0..compression_block_count)
                    .map(|_| {
                        let mut block_size = reader.read_u32::<LE>()? as u64;
                        let block = Block {
                            start: index,
                            end: index + block_size,
                        };
                        if encrypted {
                            block_size = align(block_size);
                        }
                        index += block_size;
                        Ok(block)
                    })
                    .collect::<Result<Vec<_>, super::Error>>()?,
            )
        } else {
            None
        };

        Ok(Entry {
            offset,
            compressed,
            uncompressed,
            timestamp: None,
            compression_slot: compression,
            hash: None,
            blocks,
            flags: encrypted as u8,
            compression_block_size,
        })
    }

    pub fn write_encoded<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        let mut compression_block_size = (self.compression_block_size >> 11) & 0x3f;
        if (compression_block_size << 11) != self.compression_block_size {
            compression_block_size = 0x3f;
        }
        let compression_blocks_count = if self.compression_slot.is_some() {
            self.blocks.as_ref().unwrap().len() as u32
        } else {
            0
        };
        let is_size_32_bit_safe = self.compressed <= u32::MAX as u64;
        let is_uncompressed_size_32_bit_safe = self.uncompressed <= u32::MAX as u64;
        let is_offset_32_bit_safe = self.offset <= u32::MAX as u64;

        let flags = (compression_block_size)
            | (compression_blocks_count << 6)
            | ((self.is_encrypted() as u32) << 22)
            | (self.compression_slot.map_or(0, |n| n + 1) << 23)
            | ((is_size_32_bit_safe as u32) << 29)
            | ((is_uncompressed_size_32_bit_safe as u32) << 30)
            | ((is_offset_32_bit_safe as u32) << 31);

        writer.write_u32::<LE>(flags)?;

        if compression_block_size == 0x3f {
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        if is_offset_32_bit_safe {
            writer.write_u32::<LE>(self.offset as u32)?;
        } else {
            writer.write_u64::<LE>(self.offset)?;
        }

        if is_uncompressed_size_32_bit_safe {
            writer.write_u32::<LE>(self.uncompressed as u32)?
        } else {
            writer.write_u64::<LE>(self.uncompressed)?
        }

        if self.compression_slot.is_some() {
            if is_size_32_bit_safe {
                writer.write_u32::<LE>(self.compressed as u32)?;
            } else {
                writer.write_u64::<LE>(self.compressed)?;
            }

            assert!(self.blocks.is_some());
            let blocks = self.blocks.as_ref().unwrap();
            if blocks.len() > 1 || self.is_encrypted() {
                for b in blocks {
                    let block_size = b.end - b.start;
                    writer.write_u32::<LE>(block_size.try_into().unwrap())?;
                }
            }
        }

        Ok(())
    }

    pub fn read_file<R: io::Read + io::Seek, W: io::Write>(
        &self,
        reader: &mut R,
        version: Version,
        compression: &[Option<Compression>],
        #[allow(unused)] key: &super::Key,
        #[allow(unused)] oodle: &super::Oodle,
        buf: &mut W,
    ) -> Result<(), super::Error> {
        reader.seek(io::SeekFrom::Start(self.offset))?;
        Entry::read(reader, version)?;
        #[cfg(any(feature = "compression", feature = "oodle"))]
        let data_offset = reader.stream_position()?;
        #[allow(unused_mut)]
        let mut data = reader.read_len(match self.is_encrypted() {
            true => align(self.compressed),
            false => self.compressed,
        } as usize)?;
        if self.is_encrypted() {
            #[cfg(not(feature = "encryption"))]
            return Err(super::Error::Encryption);
            #[cfg(feature = "encryption")]
            {
                let super::Key::Some(key) = key else {
                    return Err(super::Error::Encrypted);
                };
                use aes::cipher::BlockDecrypt;
                for block in data.chunks_mut(16) {
                    key.decrypt_block(aes::Block::from_mut_slice(block))
                }
                data.truncate(self.compressed as usize);
            }
        }

        #[cfg(any(feature = "compression", feature = "oodle"))]
        let ranges = {
            let offset = |index: u64| -> usize {
                (match version.version_major() >= VersionMajor::RelativeChunkOffsets {
                    true => index - (data_offset - self.offset),
                    false => index - data_offset,
                }) as usize
            };

            match &self.blocks {
                Some(blocks) => blocks
                    .iter()
                    .map(|block| offset(block.start)..offset(block.end))
                    .collect::<Vec<_>>(),
                #[allow(clippy::single_range_in_vec_init)]
                None => vec![0..data.len()],
            }
        };

        #[cfg(feature = "compression")]
        macro_rules! decompress {
            ($decompressor: ty) => {
                for range in ranges {
                    io::copy(&mut <$decompressor>::new(&data[range]), buf)?;
                }
            };
        }

        // self.compression_slot is only ever validated against compression's actual length
        // here, at first use - a legacy (pre-FNameBasedCompression) pak's hardcoded fallback
        // list (see Footer::read) can be shorter than a slot number an entry legitimately
        // references, so this must be a checked lookup, not a panicking index: an entry from
        // the wild that hits this must surface as an ordinary Result error, not abort the
        // whole process (a panic inside the extern "C" FFI boundary this crate is called
        // through can't unwind, so Rust aborts instead of returning to the caller at all).
        let resolved_compression = match self.compression_slot {
            None => None,
            Some(c) => *compression
                .get(c as usize)
                .ok_or(Error::UnknownCompressionSlot(c, compression.len()))?,
        };
        #[cfg(feature = "compression")]
        let chunk_size = if ranges.len() == 1 {
            self.uncompressed as usize
        } else {
            self.compression_block_size as usize
        };
        match resolved_compression {
            None => buf.write_all(&data)?,
            #[cfg(feature = "compression")]
            Some(Compression::Zlib) => decompress!(flate2::read::ZlibDecoder<&[u8]>),
            #[cfg(feature = "compression")]
            Some(Compression::Gzip) => decompress!(flate2::read::GzDecoder<&[u8]>),
            #[cfg(feature = "compression")]
            Some(Compression::Zstd) => {
                let mut decompressed = vec![0; self.uncompressed as usize];
                for (decomp_chunk, comp_range) in decompressed.chunks_mut(chunk_size).zip(ranges) {
                    let comp_data = &data[comp_range];
                    let mut dst: &mut [u8] = decomp_chunk;
                    let framed = zstd::stream::read::Decoder::new(comp_data)
                        .and_then(|mut dec| io::copy(&mut dec, &mut dst));
                    if framed.is_err() {
                        // Some licensee pak variants (e.g. Days Gone, unconfirmed) store
                        // raw/headerless Zstd blocks - no frame magic or descriptor, so the
                        // standard framed decoder rejects them with "Unknown frame
                        // descriptor". Each block's uncompressed size is already known from
                        // the pak index, so the raw block API is the correct fallback.
                        decompress_raw_zstd_block(decomp_chunk, comp_data)
                            .map_err(|_| Error::DecompressionFailed(Compression::Zstd))?;
                    }
                }
                buf.write_all(&decompressed)?;
            }
            #[cfg(feature = "compression")]
            Some(Compression::LZ4) => {
                let mut decompressed = vec![0; self.uncompressed as usize];
                for (decomp_chunk, comp_range) in decompressed.chunks_mut(chunk_size).zip(ranges) {
                    lz4_flex::block::decompress_into(&data[comp_range], decomp_chunk)
                        .map_err(|_| Error::DecompressionFailed(Compression::LZ4))?;
                }
                buf.write_all(&decompressed)?;
            }
            #[cfg(feature = "oodle")]
            Some(Compression::Oodle) => {
                let oodle = match oodle {
                    crate::Oodle::Some(getter) => getter().map_err(|_| super::Error::OodleFailed),
                    crate::Oodle::None => Err(super::Error::OodleFailed),
                }?;
                let mut decompressed = vec![0; self.uncompressed as usize];

                let mut compress_offset = 0;
                let mut decompress_offset = 0;
                let block_count = ranges.len();
                for range in ranges {
                    let decomp = if block_count == 1 {
                        self.uncompressed as usize
                    } else {
                        (self.compression_block_size as usize)
                            .min(self.uncompressed as usize - compress_offset)
                    };
                    let buffer = &mut data[range];
                    let out = oodle(
                        buffer,
                        &mut decompressed[decompress_offset..decompress_offset + decomp],
                    );
                    if out == 0 {
                        return Err(super::Error::DecompressionFailed(Compression::Oodle));
                    }
                    compress_offset += self.compression_block_size as usize;
                    decompress_offset += out as usize;
                }

                debug_assert_eq!(
                    decompress_offset, self.uncompressed as usize,
                    "Oodle decompression length mismatch"
                );
                buf.write_all(&decompressed)?;
            }
            #[cfg(not(feature = "oodle"))]
            Some(Compression::Oodle) => return Err(super::Error::Oodle),
            #[cfg(not(feature = "compression"))]
            _ => return Err(super::Error::Compression),
        }
        buf.flush()?;
        Ok(())
    }
}

mod test {
    #[test]
    fn test_entry() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xDD, 0x94, 0xFD, 0xC3, 0x5F, 0xF5, 0x91, 0xA9, 0x9A, 0x5E, 0x14, 0xDC, 0x9B,
            0xD3, 0x58, 0x89, 0x78, 0xA6, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = vec![];
        let entry = super::Entry::read(&mut std::io::Cursor::new(data.clone()), super::Version::V5)
            .unwrap();
        entry
            .write(&mut out, super::Version::V5, super::EntryLocation::Data)
            .unwrap();
        assert_eq!(&data, &out);
    }

    /// Regression test: a legacy (pre-FNameBasedCompression) pak version's footer never
    /// stores compression method names, so `Footer::read` fills in a hardcoded 3-entry
    /// fallback list (Zlib, Gzip, Oodle) - see footer.rs. A real-world entry can still
    /// reference compression slot 3 (0-based, a 4th method that fallback list doesn't
    /// cover), which used to index straight into that 3-element slice and panic. Because
    /// this call happens behind an `extern "C"` FFI boundary that can't unwind, the panic
    /// aborted the whole host process instead of returning an error - this must come back
    /// as an ordinary `Result::Err` instead.
    #[test]
    fn read_file_errors_instead_of_panicking_on_out_of_range_compression_slot() {
        let entry = super::Entry {
            offset: 0,
            compressed: 4,
            uncompressed: 4,
            compression_slot: Some(3),
            timestamp: None,
            hash: Some([0; 20]),
            blocks: Some(vec![]),
            flags: 0,
            compression_block_size: 0,
        };

        let mut header = vec![];
        entry
            .write(&mut header, super::Version::V3, super::EntryLocation::Data)
            .unwrap();
        header.extend_from_slice(&[0u8; 4]); // the entry's own (irrelevant-to-this-test) payload bytes

        let compression = [
            Some(super::super::Compression::Zlib),
            Some(super::super::Compression::Gzip),
            Some(super::super::Compression::Oodle),
        ];
        let mut out = vec![];

        let result = entry.read_file(
            &mut std::io::Cursor::new(header),
            super::Version::V3,
            &compression,
            &super::super::Key::None,
            &super::super::Oodle::None,
            &mut out,
        );

        assert!(matches!(
            result,
            Err(super::super::Error::UnknownCompressionSlot(3, 3))
        ));
    }

    /// Regression test: some licensee pak variants (suspected for Days Gone, unconfirmed)
    /// store raw/headerless Zstd blocks - ZSTD_compressBlock/ZSTD_decompressBlock, no
    /// frame magic or descriptor - which the standard frame-based streaming decoder
    /// rejects with "Unknown frame descriptor" (the exact error real-world testing hit).
    /// Proves the ZSTD_decompressBlock fallback in `read_file` correctly round-trips
    /// data compressed the same way, independent of any real pak file - it does not
    /// prove this is actually what any specific game uses.
    #[test]
    fn read_file_falls_back_to_raw_zstd_block_when_frame_decode_fails() {
        let original =
            b"the quick brown fox jumps over the lazy dog, again and again and again".to_vec();

        let mut compressed = vec![0u8; original.len() + 128];
        let written = unsafe {
            let cctx = zstd_sys::ZSTD_createCCtx();
            assert!(!cctx.is_null());
            let begin = zstd_sys::ZSTD_compressBegin(cctx, 0);
            assert_eq!(zstd_sys::ZSTD_isError(begin), 0);
            let written = zstd_sys::ZSTD_compressBlock(
                cctx,
                compressed.as_mut_ptr() as *mut core::ffi::c_void,
                compressed.len(),
                original.as_ptr() as *const core::ffi::c_void,
                original.len(),
            );
            zstd_sys::ZSTD_freeCCtx(cctx);
            assert_eq!(zstd_sys::ZSTD_isError(written), 0);
            written
        };
        compressed.truncate(written);

        // read_file needs a single Block spanning the whole payload so `ranges` resolves
        // to one chunk of the correct (uncompressed) size - block start/end are absolute
        // stream positions of the *compressed* bytes, which aren't known until the header
        // itself (which embeds the block) has been serialized, hence the two-pass write.
        let make_entry = |block: Option<super::Block>| super::Entry {
            offset: 0,
            compressed: compressed.len() as u64,
            uncompressed: original.len() as u64,
            compression_slot: Some(0),
            timestamp: None,
            hash: Some([0; 20]),
            blocks: Some(block.into_iter().collect()),
            flags: 0,
            compression_block_size: 0,
        };

        let mut placeholder_header = vec![];
        make_entry(Some(super::Block { start: 0, end: 0 }))
            .write(
                &mut placeholder_header,
                super::Version::V3,
                super::EntryLocation::Data,
            )
            .unwrap();
        let header_len = placeholder_header.len() as u64;

        let entry = make_entry(Some(super::Block {
            start: header_len,
            end: header_len + compressed.len() as u64,
        }));

        let mut header = vec![];
        entry
            .write(&mut header, super::Version::V3, super::EntryLocation::Data)
            .unwrap();
        assert_eq!(header.len() as u64, header_len);
        header.extend_from_slice(&compressed);

        let compression = [Some(super::super::Compression::Zstd)];
        let mut out = vec![];

        entry
            .read_file(
                &mut std::io::Cursor::new(header),
                super::Version::V3,
                &compression,
                &super::super::Key::None,
                &super::super::Oodle::None,
                &mut out,
            )
            .unwrap();

        assert_eq!(out, original);
    }
}
