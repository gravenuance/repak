use crate::ext::{BoolExt, WriteExt};

use super::{ext::ReadExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::str::FromStr;

#[derive(Debug)]
pub struct Footer {
    pub encryption_uuid: Option<u128>,
    pub encrypted: bool,
    pub magic: u32,
    pub version: Version,
    pub version_major: VersionMajor,
    pub index_offset: u64,
    pub index_size: u64,
    pub hash: [u8; 20],
    pub frozen: bool,
    pub compression: Vec<Option<Compression>>,
}

impl Footer {
    pub fn read<R: std::io::Read>(reader: &mut R, version: Version) -> Result<Self, super::Error> {
        let encryption_uuid = (version.version_major() >= VersionMajor::EncryptionKeyGuid)
            .then_try(|| reader.read_u128::<LE>())?;
        let encrypted =
            version.version_major() >= VersionMajor::IndexEncryption && reader.read_bool()?;
        let magic = reader.read_u32::<LE>()?;
        let version_major =
            VersionMajor::from_repr(reader.read_u32::<LE>()?).unwrap_or(version.version_major());
        let index_offset = reader.read_u64::<LE>()?;
        let index_size = reader.read_u64::<LE>()?;
        let hash = reader.read_guid()?;
        let frozen = version.version_major() == VersionMajor::FrozenIndex && reader.read_bool()?;
        let compression = {
            let mut compression = Vec::with_capacity(match version {
                ver if ver < Version::V8A => 0,
                ver if ver < Version::V8B => 4,
                _ => 5,
            });
            for _ in 0..compression.capacity() {
                compression.push(
                    Compression::from_str(
                        &reader
                            .read_len(32)?
                            .iter()
                            // filter out whitespace and convert to char
                            .filter_map(|&ch| (ch != 0).then_some(ch as char))
                            .collect::<String>(),
                    )
                    .ok(),
                )
            }
            if version.version_major() < VersionMajor::FNameBasedCompression {
                // Before FNameBasedCompression (UE4 < 4.22) the pak stores no compression
                // names, and `FPakEntry::CompressionMethod` is an ECompressionFlags BITMASK,
                // not an index into a codec table:
                //     COMPRESS_ZLIB = 0x01, COMPRESS_GZIP = 0x02, COMPRESS_Custom = 0x04
                // `Entry::read` already normalises the on-disk value to `n - 1`, so this list
                // is indexed by (flag - 1); index 2 would mean flag 0x03 (ZLIB|GZIP), which is
                // not a real codec, hence the explicit `None` hole.
                //
                // Verified against the real Days Gone pak (UE4.17, 216 747 entries): the only
                // values that ever appear are 0 and 4 - never 1, 2 or 3 - which is a bitmask
                // signature, not an index range. Every 0x04 block decompresses byte-exactly
                // with Oodle (Bend statically links it, which is why the game ships no
                // oo2core DLL). Reading 0x04 as "the 4th entry of a codec list" is a category
                // error, and is why Zstd and LZ4 were each cleanly rejected when tried here.
                compression.push(Some(Compression::Zlib)); // flag 0x01
                compression.push(Some(Compression::Gzip)); // flag 0x02
                compression.push(None); // flag 0x03 = ZLIB|GZIP, not a codec
                compression.push(Some(Compression::Oodle)); // flag 0x04 = COMPRESS_Custom
            }
            compression
        };
        if super::MAGIC != magic {
            return Err(super::Error::Magic(magic));
        }
        if version.version_major() != version_major {
            return Err(super::Error::Version {
                used: version.version_major(),
                version: version_major,
            });
        }
        Ok(Self {
            encryption_uuid,
            encrypted,
            magic,
            version,
            version_major,
            index_offset,
            index_size,
            hash,
            frozen,
            compression,
        })
    }

    pub fn write<W: std::io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        if self.version_major >= VersionMajor::EncryptionKeyGuid {
            writer.write_u128::<LE>(0)?;
        }
        if self.version_major >= VersionMajor::IndexEncryption {
            writer.write_bool(self.encrypted)?;
        }
        writer.write_u32::<LE>(self.magic)?;
        writer.write_u32::<LE>(self.version_major as u32)?;
        writer.write_u64::<LE>(self.index_offset)?;
        writer.write_u64::<LE>(self.index_size)?;
        writer.write_all(&self.hash)?;
        if self.version_major == VersionMajor::FrozenIndex {
            writer.write_bool(self.frozen)?;
        }
        let algo_size = match self.version {
            ver if ver < Version::V8A => 0,
            ver if ver < Version::V8B => 4,
            _ => 5,
        };
        // TODO: handle if compression.len() > algo_size
        for i in 0..algo_size {
            let mut name = [0; 32];
            if let Some(algo) = self.compression.get(i).cloned().flatten() {
                for (i, b) in algo.to_string().as_bytes().iter().enumerate() {
                    name[i] = *b;
                }
            }
            writer.write_all(&name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Footer;
    use crate::{Compression, Version, VersionMajor};

    /// Regression test: a legacy (pre-FNameBasedCompression) pak stores no compression
    /// method names, so `Footer::read` fills in a fallback list. That list is indexed by
    /// ECompressionFlags value minus one (see `Footer::read`), so the ordering is
    /// Zlib(0x01), Gzip(0x02), a `None` hole for the impossible 0x03, then Oodle(0x04) -
    /// NOT "the first four codecs in some arbitrary order". Confirmed against the real
    /// Days Gone pak, where the only observed values are 0 and 4 and every 0x04 block
    /// decompresses byte-exactly as Oodle.
    #[test]
    fn read_fills_in_legacy_compression_flags_indexed_by_flag_value() {
        let footer = Footer {
            encryption_uuid: None,
            encrypted: false,
            magic: super::super::MAGIC,
            version: Version::V3,
            version_major: VersionMajor::CompressionEncryption,
            index_offset: 0,
            index_size: 0,
            hash: [0; 20],
            frozen: false,
            compression: vec![],
        };

        let mut buf = vec![];
        footer.write(&mut buf).unwrap();
        let read_back = Footer::read(&mut std::io::Cursor::new(buf), Version::V3).unwrap();

        assert_eq!(
            read_back.compression,
            vec![
                Some(Compression::Zlib), // ECompressionFlags 0x01
                Some(Compression::Gzip), // 0x02
                None,                    // 0x03 (ZLIB|GZIP) is not a real codec
                Some(Compression::Oodle) // 0x04 COMPRESS_Custom - Oodle in practice
            ]
        );
    }
}
