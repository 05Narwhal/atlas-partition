// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Partition maps. Each one yields slices of a `BlockSource`.
//!
//! Every reader has the same shape: `read(source) -> Result<Option<PartitionMap>>`.
//! `Ok(None)` means the map's signature is absent. `Err` means the signature
//! is there but the map is damaged beyond use. Damage the reader could work
//! around (a bad primary GPT header with a good backup, an entry that points
//! past the end of the disk) is recorded in [`PartitionMap::damage`] and the
//! rest of the map is still returned.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use atlas_fs_core::io::file::FileSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let source = FileSource::open(Path::new("disk.img"))?;
//! if let Some(map) = atlas_partition::read(&source)? {
//!     for partition in &map.partitions {
//!         println!("{} at {} for {} bytes", partition.number, partition.start, partition.len);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::fmt;
use std::sync::Arc;

use atlas_fs_core::error::{Corruption, Result};
use atlas_fs_core::io::block::{BlockSource, Slice};

pub mod apm;
pub mod gpt;
pub mod mbr;

/// Which kind of map a disk carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// GUID Partition Table.
    Gpt,
    /// Master Boot Record, including extended partitions.
    Mbr,
    /// Apple Partition Map.
    Apm,
}

/// A GUID in its on-disk byte order (the first three fields little-endian,
/// as GPT stores them).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Builds a GUID from the fields of its text form
    /// `d1-d2-d3-d4[0..2]-d4[2..8]`.
    pub const fn from_fields(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        let a = d1.to_le_bytes();
        let b = d2.to_le_bytes();
        let c = d3.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4],
            d4[5], d4[6], d4[7],
        ])
    }

    /// The all-zero GUID, which marks an unused GPT entry.
    pub const ZERO: Self = Self([0; 16]);

    /// HFS+ and HFSX (`48465300-0000-11AA-AA11-00306543ECAC`).
    pub const HFS_PLUS: Self = Self::from_fields(
        0x4846_5300,
        0x0000,
        0x11AA,
        [0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC],
    );
    /// APFS container (`7C3457EF-0000-11AA-AA11-00306543ECAC`).
    pub const APFS: Self = Self::from_fields(
        0x7C34_57EF,
        0x0000,
        0x11AA,
        [0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC],
    );
    /// Core Storage logical volume (`53746F72-6167-11AA-AA11-00306543ECAC`).
    pub const CORE_STORAGE: Self = Self::from_fields(
        0x5374_6F72,
        0x6167,
        0x11AA,
        [0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC],
    );
    /// EFI System partition (`C12A7328-F81F-11D2-BA4B-00A0C93EC93B`).
    pub const EFI_SYSTEM: Self = Self::from_fields(
        0xC12A_7328,
        0xF81F,
        0x11D2,
        [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    );
    /// Microsoft basic data: FAT, exFAT or NTFS (`EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`).
    pub const MICROSOFT_BASIC_DATA: Self = Self::from_fields(
        0xEBD0_A0A2,
        0xB9E5,
        0x4433,
        [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
    );
    /// Linux filesystem data (`0FC63DAF-8483-4772-8E79-3D69D8477DE4`).
    pub const LINUX_DATA: Self = Self::from_fields(
        0x0FC6_3DAF,
        0x8483,
        0x4772,
        [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
    );
}

impl fmt::Display for Guid {
    /// Upper-case text form, `7C3457EF-0000-11AA-AA11-00306543ECAC`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// The type a map gives a partition, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionType {
    /// A GPT type GUID.
    Gpt(Guid),
    /// An MBR system ID byte.
    Mbr(u8),
    /// An APM type string such as `Apple_HFS`, trimmed at the first NUL.
    Apm(String),
}

/// What a partition's type suggests it contains. Only a hint: the probe
/// registry looks at the contents before anything is mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TypeHint {
    /// HFS or HFS+ (the maps do not tell them apart).
    Hfs,
    /// An APFS container.
    Apfs,
    /// A Core Storage logical volume.
    CoreStorage,
    /// The EFI System partition (FAT).
    EfiSystem,
    /// FAT, exFAT or NTFS.
    Microsoft,
    /// A Linux filesystem.
    Linux,
    /// Free space, the map itself, drivers, or patches: nothing to mount.
    /// APM lists these as partitions.
    NotData,
    /// Anything else.
    Other,
}

/// One partition, in bytes of the source the map was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Partition {
    /// The partition's number as tools show it: GPT entry index + 1, MBR 1 to
    /// 4 for primary and 5 onwards for logical, APM map entry index + 1.
    pub number: u32,
    /// Byte offset in the source.
    pub start: u64,
    /// Length in bytes. Clamped to the end of the source when the map says
    /// more; `truncated` is then set.
    pub len: u64,
    /// The map claimed more bytes than the source has.
    pub truncated: bool,
    /// The type as the map stores it.
    pub kind: PartitionType,
    /// What the type suggests.
    pub hint: TypeHint,
    /// The partition's name, if the map stores one (GPT, APM).
    pub name: Option<String>,
}

impl Partition {
    /// The partition's bytes as a source of their own.
    pub fn slice(&self, source: Arc<dyn BlockSource>) -> Result<Slice> {
        Slice::new(source, self.start, self.len)
    }
}

/// A partition map as read from a source.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PartitionMap {
    /// Which kind of map.
    pub scheme: Scheme,
    /// The block size the map counts in: the logical sector size for GPT and
    /// MBR, the driver descriptor's block size for APM.
    pub block_size: u32,
    /// Partitions in map order. Unused entries and entries of zero length are
    /// left out; entries that start past the end of the source are left out
    /// and recorded in `damage`.
    pub partitions: Vec<Partition>,
    /// Problems the reader worked around.
    pub damage: Vec<Corruption>,
}

/// Reads whichever partition map the source carries.
///
/// Order: GPT (at the source's sector size, then 512, then 4096), then Apple
/// Partition Map, then MBR. `Ok(None)` means no map: a bare volume or a blank
/// disk. A GPT whose signature was seen but could not be read is an error; so
/// is a protective MBR (`0xEE`) with no readable GPT.
pub fn read(source: &dyn BlockSource) -> Result<Option<PartitionMap>> {
    let mut sizes = Vec::with_capacity(3);
    for size in [source.sector_size(), 512, 4096] {
        if !sizes.contains(&size) {
            sizes.push(size);
        }
    }
    let mut gpt_error = None;
    for size in sizes {
        match gpt::read_with_sector_size(source, size) {
            Ok(Some(map)) => return Ok(Some(map)),
            Ok(None) => {}
            Err(e) => {
                gpt_error.get_or_insert(e);
            }
        }
    }
    if let Some(e) = gpt_error {
        return Err(e);
    }

    if let Some(map) = apm::read(source)? {
        return Ok(Some(map));
    }

    let Some(map) = mbr::read(source)? else {
        return Ok(None);
    };
    if map
        .partitions
        .iter()
        .any(|p| p.kind == PartitionType::Mbr(0xEE))
    {
        return Err(atlas_fs_core::error::Error::Corrupt(Corruption::new(
            "MBR",
            atlas_fs_core::error::Location::Unspecified,
            atlas_fs_core::error::CorruptKind::Other("protective MBR but no readable GPT"),
        )));
    }
    Ok(Some(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_fs_core::error::{CorruptKind, Error};
    use atlas_fs_core::io::block::MemSource;

    fn gpt_disk(ss: usize, total_sectors: usize) -> Vec<u8> {
        gpt::testutil::build(
            ss,
            total_sectors,
            &[
                gpt::testutil::Spec {
                    type_guid: Guid::HFS_PLUS.0,
                    first: 6,
                    last: 100,
                    name: "Mac",
                },
                gpt::testutil::Spec {
                    type_guid: Guid::EFI_SYSTEM.0,
                    first: 101,
                    last: 150,
                    name: "EFI",
                },
            ],
        )
    }

    #[test]
    fn blank_source_has_no_map() {
        assert!(read(&MemSource::new(vec![0u8; 1 << 20])).unwrap().is_none());
        assert!(read(&MemSource::new(Vec::new())).unwrap().is_none());
    }

    #[test]
    fn gpt_beats_a_hybrid_mbr() {
        let mut disk = gpt_disk(512, 2048);
        mbr::testutil::put(&mut disk[..512], 0, 0, 0xEE, 1, 100);
        mbr::testutil::put(&mut disk[..512], 1, 0x80, 0xAF, 64, 100);
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.scheme, Scheme::Gpt);
        assert_eq!(map.partitions.len(), 2);
    }

    #[test]
    fn gpt_on_4096_sector_disk() {
        let disk = gpt_disk(4096, 256);
        // Reports its real sector size.
        let map = read(&MemSource::with_sector_size(disk.clone(), 4096))
            .unwrap()
            .unwrap();
        assert_eq!((map.scheme, map.block_size), (Scheme::Gpt, 4096));
        assert_eq!(map.partitions[0].start, 6 * 4096);
        // Reports 512 (an image file of a 4Kn disk): found by trying 4096.
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!((map.scheme, map.block_size), (Scheme::Gpt, 4096));
    }

    #[test]
    fn gpt_on_512_disk_reporting_4096() {
        let disk = gpt_disk(512, 2048);
        let map = read(&MemSource::with_sector_size(disk, 4096))
            .unwrap()
            .unwrap();
        assert_eq!(map.block_size, 512);
    }

    #[test]
    fn damaged_gpt_is_an_error_not_a_fallthrough() {
        let mut disk = gpt_disk(512, 2048);
        disk[512 + 48] ^= 0xFF;
        disk[2047 * 512 + 48] ^= 0xFF;
        // Even with a plausible MBR in front.
        mbr::testutil::put(&mut disk[..512], 0, 0, 0xEE, 1, 100);
        assert!(matches!(
            read(&MemSource::new(disk)),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn protective_mbr_without_gpt_is_an_error() {
        let mut disk = vec![0u8; 1 << 20];
        mbr::testutil::put(&mut disk[..512], 0, 0, 0xEE, 1, 2047);
        match read(&MemSource::new(disk)) {
            Err(Error::Corrupt(c)) => {
                assert!(matches!(c.kind, CorruptKind::Other(t) if t.contains("protective")));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn plain_mbr_is_returned() {
        let mut disk = vec![0u8; 1 << 20];
        mbr::testutil::put(&mut disk[..512], 0, 0x80, 0x83, 64, 100);
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.scheme, Scheme::Mbr);
    }

    #[test]
    fn apm_is_returned() {
        let mut disk = vec![0u8; 1 << 20];
        disk[..2].copy_from_slice(b"ER");
        disk[2..4].copy_from_slice(&512u16.to_be_bytes());
        let e = &mut disk[512..592];
        e[..2].copy_from_slice(b"PM");
        e[4..8].copy_from_slice(&1u32.to_be_bytes());
        e[8..12].copy_from_slice(&64u32.to_be_bytes());
        e[12..16].copy_from_slice(&100u32.to_be_bytes());
        e[48..57].copy_from_slice(b"Apple_HFS");
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.scheme, Scheme::Apm);
        assert_eq!(map.partitions[0].hint, TypeHint::Hfs);
    }

    #[test]
    fn fat_boot_sector_is_not_a_map() {
        let mut disk = vec![0u8; 1 << 20];
        disk[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        disk[3..11].copy_from_slice(b"MSDOS5.0");
        disk[446 + 16] = 0x29; // extended boot signature lands in an entry
        disk[510] = 0x55;
        disk[511] = 0xAA;
        assert!(read(&MemSource::new(disk)).unwrap().is_none());
    }

    #[test]
    fn partition_slice_respects_clamped_length() {
        use std::sync::Arc;
        let disk = gpt_disk(512, 2048);
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(disk));
        let map = read(src.as_ref()).unwrap().unwrap();
        let slice = map.partitions[0].slice(src).unwrap();
        assert_eq!(slice.len(), map.partitions[0].len);
    }
}
