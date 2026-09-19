use crate::{
    ext::{BoolExt, WriteExt},
    Hash,
};

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
    pub hash: Hash,
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
        let hash = Hash(reader.read_guid()?);
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
                compression.push(Some(Compression::Zlib));
                compression.push(Some(Compression::Gzip));
                compression.push(Some(Compression::Oodle));
                // Slot 3: Zstd is the leading candidate (it's slot 3 in both this crate's
                // own Compression enum and UAssetAPI's independently-written
                // PakCompression). The standard framed Zstd decoder cleanly rejected a
                // real Days Gone V3 pak entry ("Unknown frame descriptor"), but that only
                // rules out the *framed* form - entry.rs's Zstd arm now also falls back to
                // ZSTD_decompressBlock for headerless raw blocks, which hasn't been tested
                // against real data yet. LZ4 was tried here too and also cleanly rejected
                // ("LZ4 decompression failed"), so it's been moved out of this slot back
                // to unused-for-now rather than sitting where Zstd's raw-block form has a
                // real, untested hypothesis.
                compression.push(Some(Compression::Zstd));
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
        writer.write_all(&self.hash.0)?;
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
    use super::{Footer, Hash};
    use crate::{Compression, Version, VersionMajor};

    /// Regression test: a legacy (pre-FNameBasedCompression) pak version's footer never
    /// stores compression method names on disk, so `Footer::read` fills in a hardcoded
    /// fallback list instead of reading one. This list must have exactly as many entries
    /// as any real-world entry's compression slot can reference - see entry.rs's own
    /// regression test for what happens when it doesn't (a slot 3 entry from a real V3
    /// pak used to panic on a 3-element list; the 4th entry, Zstd, was missing).
    #[test]
    fn read_fills_in_four_hardcoded_legacy_compression_methods() {
        let footer = Footer {
            encryption_uuid: None,
            encrypted: false,
            magic: super::super::MAGIC,
            version: Version::V3,
            version_major: VersionMajor::CompressionEncryption,
            index_offset: 0,
            index_size: 0,
            hash: Hash([0; 20]),
            frozen: false,
            compression: vec![],
        };

        let mut buf = vec![];
        footer.write(&mut buf).unwrap();
        let read_back = Footer::read(&mut std::io::Cursor::new(buf), Version::V3).unwrap();

        assert_eq!(
            read_back.compression,
            vec![
                Some(Compression::Zlib),
                Some(Compression::Gzip),
                Some(Compression::Oodle),
                Some(Compression::Zstd),
            ]
        );
    }
}
