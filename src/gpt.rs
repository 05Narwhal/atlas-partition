// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! GUID Partition Table reader.
//!
//! The header sits at LBA 1 with a backup at the last LBA. Everything is
//! little-endian. A bad primary (missing, header CRC or entry-array CRC
//! failure) falls back to the backup; the fallback is recorded in
//! [`PartitionMap::damage`].

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::BlockSource;

use super::{Guid, Partition, PartitionMap, PartitionType, Scheme, TypeHint};

const STRUCTURE: &str = "GPT";
const SIGNATURE: &[u8; 8] = b"EFI PART";
/// Smallest legal header size (the fields through the entry-array CRC).
const MIN_HEADER_SIZE: u32 = 92;
/// Entries are at least 128 bytes and a multiple of 128.
const ENTRY_SIZE_UNIT: u32 = 128;
/// Upper bound on the entry array, `count * entry size`.
const MAX_ENTRY_ARRAY: u64 = 4 * 1024 * 1024;

/// Reads the GPT using the source's own logical sector size.
///
/// `Ok(None)` when neither header carries the signature.
pub fn read(source: &dyn BlockSource) -> Result<Option<PartitionMap>> {
    read_with_sector_size(source, source.sector_size())
}

/// Reads the GPT assuming `sector_size`-byte LBAs. The dispatcher uses this to
/// try 512 and 4096 on sources that report the wrong one.
pub fn read_with_sector_size(
    source: &dyn BlockSource,
    sector_size: u32,
) -> Result<Option<PartitionMap>> {
    if !sector_size.is_power_of_two() || !(512..=65536).contains(&sector_size) {
        return Ok(None);
    }
    let ss = u64::from(sector_size);

    // Primary header at LBA 1.
    let primary_sector = read_sector(source, 1, ss)?;
    let primary_seen = primary_sector
        .as_deref()
        .is_some_and(|s| s.get(..8) == Some(SIGNATURE.as_slice()));
    let mut primary_failure = None;
    if let Some(sector) = primary_sector.as_deref().filter(|_| primary_seen) {
        match load(source, sector, sector_size, 1) {
            Ok(map) => return Ok(Some(map)),
            Err(Failure::Io(e)) => return Err(e),
            Err(Failure::Bad(c)) => primary_failure = Some(c),
        }
    }

    // Backup header at the last LBA.
    let last_lba = source.len().checked_div(ss).and_then(|n| n.checked_sub(1));
    let mut backup_failure = None;
    if let Some(last) = last_lba.filter(|&l| l > 1)
        && let Some(sector) = read_sector(source, last, ss)?
        && sector.get(..8) == Some(SIGNATURE.as_slice())
    {
        match load(source, &sector, sector_size, last) {
            Ok(mut map) => {
                let why = primary_failure.unwrap_or(Corruption::new(
                    STRUCTURE,
                    Location::Byte(ss),
                    CorruptKind::Other("primary header missing, used the backup"),
                ));
                map.damage.insert(0, why);
                return Ok(Some(map));
            }
            Err(Failure::Io(e)) => return Err(e),
            Err(Failure::Bad(c)) => backup_failure = Some(c),
        }
    }

    match primary_failure.or(backup_failure) {
        Some(c) => Err(Error::Corrupt(c)),
        None => Ok(None),
    }
}

/// Why one header could not be used.
enum Failure {
    /// The header or its array is damaged; the other copy may still work.
    Bad(Corruption),
    /// A real read error. Not recoverable by trying the other copy.
    Io(Error),
}

impl From<Corruption> for Failure {
    fn from(c: Corruption) -> Self {
        Self::Bad(c)
    }
}

fn bad(location: Location, kind: CorruptKind) -> Failure {
    Failure::Bad(Corruption::new(STRUCTURE, location, kind))
}

/// Reads one sector at `lba`. `None` when it lies outside the source.
fn read_sector(source: &dyn BlockSource, lba: u64, ss: u64) -> Result<Option<Vec<u8>>> {
    let Some(offset) = lba.checked_mul(ss) else {
        return Ok(None);
    };
    read_bytes(source, offset, ss)
}

/// Reads `len` bytes at `offset`. `None` when the range is outside the source.
fn read_bytes(source: &dyn BlockSource, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
    match offset.checked_add(len) {
        Some(end) if end <= source.len() => {}
        _ => return Ok(None),
    }
    let Ok(len) = usize::try_from(len) else {
        return Ok(None);
    };
    let mut buf = vec![0u8; len];
    source.read_at(offset, &mut buf)?;
    Ok(Some(buf))
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(buf.get(at..end)?.try_into().ok()?))
}

fn le_u64(buf: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_le_bytes(buf.get(at..end)?.try_into().ok()?))
}

/// Validates the header in `sector` (read from `lba`) and loads the entries.
fn load(
    source: &dyn BlockSource,
    sector: &[u8],
    sector_size: u32,
    lba: u64,
) -> std::result::Result<PartitionMap, Failure> {
    let ss = u64::from(sector_size);
    let here = Location::Byte(lba.saturating_mul(ss));
    let truncated = || {
        bad(
            here,
            CorruptKind::Truncated {
                needed: 92,
                available: u64::try_from(sector.len()).unwrap_or(u64::MAX),
            },
        )
    };

    let header_size = le_u32(sector, 12).ok_or_else(truncated)?;
    if header_size < MIN_HEADER_SIZE || header_size > sector_size {
        return Err(bad(
            here,
            CorruptKind::InvalidValue {
                field: "header size",
                value: u64::from(header_size),
            },
        ));
    }
    let header_len = usize::try_from(header_size).map_err(|_| truncated())?;
    let mut header = sector.get(..header_len).ok_or_else(truncated)?.to_vec();
    let stored_crc = le_u32(&header, 16).ok_or_else(truncated)?;
    header.get_mut(16..20).ok_or_else(truncated)?.fill(0);
    if crc32(&header) != stored_crc {
        return Err(bad(here, CorruptKind::Other("header CRC32 does not match")));
    }

    let my_lba = le_u64(sector, 24).ok_or_else(truncated)?;
    if my_lba != lba {
        return Err(bad(
            here,
            CorruptKind::InvalidValue {
                field: "my LBA",
                value: my_lba,
            },
        ));
    }
    let entries_lba = le_u64(sector, 72).ok_or_else(truncated)?;
    let count = le_u32(sector, 80).ok_or_else(truncated)?;
    let entry_size = le_u32(sector, 84).ok_or_else(truncated)?;
    let array_crc = le_u32(sector, 88).ok_or_else(truncated)?;

    if entry_size < ENTRY_SIZE_UNIT || entry_size % ENTRY_SIZE_UNIT != 0 {
        return Err(bad(
            here,
            CorruptKind::InvalidValue {
                field: "partition entry size",
                value: u64::from(entry_size),
            },
        ));
    }
    let array_len = u64::from(count)
        .checked_mul(u64::from(entry_size))
        .filter(|&n| n <= MAX_ENTRY_ARRAY)
        .ok_or(bad(
            here,
            CorruptKind::LimitExceeded {
                what: "partition entry array bytes",
                limit: MAX_ENTRY_ARRAY,
            },
        ))?;
    let array_off = entries_lba.checked_mul(ss).ok_or(bad(
        here,
        CorruptKind::Overflow {
            field: "entry array offset",
        },
    ))?;
    let array = match read_bytes(source, array_off, array_len) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return Err(bad(
                Location::Byte(array_off),
                CorruptKind::Truncated {
                    needed: array_len,
                    available: source.len().saturating_sub(array_off),
                },
            ));
        }
        Err(e) => return Err(Failure::Io(e)),
    };
    if crc32(&array) != array_crc {
        return Err(bad(
            Location::Byte(array_off),
            CorruptKind::Other("entry array CRC32 does not match"),
        ));
    }

    let mut partitions = Vec::new();
    let mut damage = Vec::new();
    let entry_len = usize::try_from(entry_size).map_err(|_| truncated())?;
    for (index, entry) in array.chunks_exact(entry_len).enumerate() {
        let location = u64::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(u64::from(entry_size)))
            .and_then(|o| o.checked_add(array_off))
            .map_or(Location::Unspecified, Location::Byte);
        match parse_entry(entry, index, sector_size, source.len()) {
            Ok(Some(p)) => partitions.push(p),
            Ok(None) => {}
            Err(kind) => damage.push(Corruption::new("GPT partition entry", location, kind)),
        }
    }

    Ok(PartitionMap {
        scheme: Scheme::Gpt,
        block_size: sector_size,
        partitions,
        damage,
    })
}

/// One entry. `Ok(None)` for an unused entry.
fn parse_entry(
    entry: &[u8],
    index: usize,
    sector_size: u32,
    source_len: u64,
) -> std::result::Result<Option<Partition>, CorruptKind> {
    let short = CorruptKind::Truncated {
        needed: 128,
        available: u64::try_from(entry.len()).unwrap_or(u64::MAX),
    };
    let type_bytes: [u8; 16] = entry
        .get(..16)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| short.clone())?;
    let kind = Guid(type_bytes);
    if kind == Guid::ZERO {
        return Ok(None);
    }
    let first = le_u64(entry, 32).ok_or_else(|| short.clone())?;
    let last = le_u64(entry, 40).ok_or_else(|| short.clone())?;
    let sectors = last
        .checked_sub(first)
        .and_then(|n| n.checked_add(1))
        .ok_or(CorruptKind::InvalidValue {
            field: "last LBA",
            value: last,
        })?;
    let ss = u64::from(sector_size);
    let start = first
        .checked_mul(ss)
        .ok_or(CorruptKind::Overflow { field: "first LBA" })?;
    let len = sectors
        .checked_mul(ss)
        .ok_or(CorruptKind::Overflow { field: "last LBA" })?;
    let (start, len, truncated) = place(start, len, source_len)?;

    let name_bytes = entry.get(56..128).ok_or(short)?;
    let units = name_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0);
    let name: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();

    let number = index
        .checked_add(1)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(CorruptKind::Overflow {
            field: "entry index",
        })?;
    Ok(Some(Partition {
        number,
        start,
        len,
        truncated,
        kind: PartitionType::Gpt(kind),
        hint: hint(kind),
        name: Some(name),
    }))
}

/// Clamps a partition to the source. Starting at or past the end is an error
/// (the caller records it as damage).
fn place(
    start: u64,
    len: u64,
    source_len: u64,
) -> std::result::Result<(u64, u64, bool), CorruptKind> {
    if start >= source_len {
        return Err(CorruptKind::OutOfRange {
            field: "partition start",
            value: start,
            limit_name: "source size",
            limit: source_len,
        });
    }
    let room = source_len.saturating_sub(start);
    if len > room {
        Ok((start, room, true))
    } else {
        Ok((start, len, false))
    }
}

fn hint(kind: Guid) -> TypeHint {
    if kind == Guid::HFS_PLUS {
        TypeHint::Hfs
    } else if kind == Guid::APFS {
        TypeHint::Apfs
    } else if kind == Guid::CORE_STORAGE {
        TypeHint::CoreStorage
    } else if kind == Guid::EFI_SYSTEM {
        TypeHint::EfiSystem
    } else if kind == Guid::MICROSOFT_BASIC_DATA {
        TypeHint::Microsoft
    } else if kind == Guid::LINUX_DATA {
        TypeHint::Linux
    } else {
        TypeHint::Other
    }
}

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Fixture builder shared with the dispatcher tests.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(missing_docs)]
pub mod testutil {
    use super::crc32;

    pub struct Spec {
        pub type_guid: [u8; 16],
        pub first: u64,
        pub last: u64,
        pub name: &'static str,
    }

    /// A disk of `total_sectors` with primary and backup GPT, 128 entries.
    pub fn build(ss: usize, total_sectors: usize, specs: &[Spec]) -> Vec<u8> {
        const ENTRIES: usize = 128;
        let mut disk = vec![0u8; ss * total_sectors];
        let mut array = vec![0u8; ENTRIES * 128];
        for (i, s) in specs.iter().enumerate() {
            let e = &mut array[i * 128..(i + 1) * 128];
            e[..16].copy_from_slice(&s.type_guid);
            e[16..32].copy_from_slice(&[i as u8 + 1; 16]);
            e[32..40].copy_from_slice(&s.first.to_le_bytes());
            e[40..48].copy_from_slice(&s.last.to_le_bytes());
            for (j, u) in s.name.encode_utf16().enumerate() {
                e[56 + j * 2..58 + j * 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        let array_sectors = array.len().div_ceil(ss);
        let last_lba = total_sectors - 1;
        let backup_array_lba = last_lba - array_sectors;
        let array_crc = crc32(&array);

        let header = |my: usize, alt: usize, entries_lba: usize| {
            let mut h = vec![0u8; 92];
            h[..8].copy_from_slice(b"EFI PART");
            h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            h[12..16].copy_from_slice(&92u32.to_le_bytes());
            h[24..32].copy_from_slice(&(my as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(alt as u64).to_le_bytes());
            h[40..48].copy_from_slice(&((2 + array_sectors) as u64).to_le_bytes());
            h[48..56].copy_from_slice(&((backup_array_lba - 1) as u64).to_le_bytes());
            h[56..72].copy_from_slice(&[0xD1; 16]);
            h[72..80].copy_from_slice(&(entries_lba as u64).to_le_bytes());
            h[80..84].copy_from_slice(&(ENTRIES as u32).to_le_bytes());
            h[84..88].copy_from_slice(&128u32.to_le_bytes());
            h[88..92].copy_from_slice(&array_crc.to_le_bytes());
            let crc = crc32(&h);
            h[16..20].copy_from_slice(&crc.to_le_bytes());
            h
        };

        let p = header(1, last_lba, 2);
        disk[ss..ss + 92].copy_from_slice(&p);
        disk[2 * ss..2 * ss + array.len()].copy_from_slice(&array);
        let b = header(last_lba, 1, backup_array_lba);
        disk[last_lba * ss..last_lba * ss + 92].copy_from_slice(&b);
        disk[backup_array_lba * ss..backup_array_lba * ss + array.len()].copy_from_slice(&array);
        disk
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{Spec, build};
    use super::*;
    use atlas_fs_core::io::block::MemSource;

    fn spec(type_guid: Guid, first: u64, last: u64, name: &'static str) -> Spec {
        Spec {
            type_guid: type_guid.0,
            first,
            last,
            name,
        }
    }

    /// 1 MiB, 512-byte sectors: EFI at 40..=2047/2 etc.
    fn good_disk() -> Vec<u8> {
        build(
            512,
            2048,
            &[
                spec(Guid::EFI_SYSTEM, 40, 199, "EFI"),
                spec(Guid::HFS_PLUS, 200, 999, "Macintosh HD"),
                spec(Guid([7; 16]), 1000, 1500, "odd"),
            ],
        )
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn guid_display_hfs_plus() {
        assert_eq!(
            Guid::HFS_PLUS.to_string(),
            "48465300-0000-11AA-AA11-00306543ECAC"
        );
    }

    #[test]
    fn good_map() {
        let src = MemSource::new(good_disk());
        let map = read(&src).unwrap().unwrap();
        assert_eq!(map.scheme, Scheme::Gpt);
        assert_eq!(map.block_size, 512);
        assert!(map.damage.is_empty(), "{:?}", map.damage);
        assert_eq!(map.partitions.len(), 3);
        let p = &map.partitions[1];
        assert_eq!(p.number, 2);
        assert_eq!(p.start, 200 * 512);
        assert_eq!(p.len, 800 * 512);
        assert!(!p.truncated);
        assert_eq!(p.hint, TypeHint::Hfs);
        assert_eq!(p.kind, PartitionType::Gpt(Guid::HFS_PLUS));
        assert_eq!(p.name.as_deref(), Some("Macintosh HD"));
        assert_eq!(map.partitions[0].hint, TypeHint::EfiSystem);
        assert_eq!(map.partitions[2].hint, TypeHint::Other);
        assert_eq!(map.partitions[2].number, 3);
    }

    #[test]
    fn blank_and_tiny_sources_are_none() {
        assert!(read(&MemSource::new(vec![0u8; 1 << 20])).unwrap().is_none());
        assert!(read(&MemSource::new(vec![0u8; 100])).unwrap().is_none());
        assert!(read(&MemSource::new(Vec::new())).unwrap().is_none());
    }

    #[test]
    fn backup_header_recovers_missing_primary() {
        let mut disk = good_disk();
        disk[512..1024].fill(0);
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 3);
        assert_eq!(map.damage.len(), 1);
    }

    #[test]
    fn backup_header_recovers_primary_header_crc_failure() {
        let mut disk = good_disk();
        disk[512 + 48] ^= 0xFF; // last usable LBA, inside the CRC
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 3);
        assert_eq!(map.damage.len(), 1);
        assert!(map.damage[0].to_string().contains("header CRC32"));
    }

    #[test]
    fn backup_recovers_primary_entry_array_crc_failure() {
        let mut disk = good_disk();
        disk[2 * 512 + 40] ^= 1; // flip a bit in entry 0
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 3);
        assert_eq!(map.partitions[0].start, 40 * 512);
        assert!(map.damage[0].to_string().contains("entry array CRC32"));
    }

    #[test]
    fn both_headers_bad_is_error() {
        let mut disk = good_disk();
        disk[512 + 48] ^= 0xFF;
        let last = 2047 * 512;
        disk[last + 48] ^= 0xFF;
        assert!(matches!(
            read(&MemSource::new(disk)),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn truncated_source_loses_the_backup_but_primary_works() {
        let disk = good_disk();
        // Cut inside the last partition: partition 3 (1000..=1500) is clamped.
        let cut = 1200 * 512;
        let map = read(&MemSource::new(disk[..cut].to_vec()))
            .unwrap()
            .unwrap();
        assert_eq!(map.partitions.len(), 3);
        let p = &map.partitions[2];
        assert!(p.truncated);
        assert_eq!(p.start, 1000 * 512);
        assert_eq!(p.len, 200 * 512);
        assert!(!map.partitions[1].truncated);
    }

    #[test]
    fn truncated_before_entry_array_end_is_error() {
        let disk = good_disk();
        // Keep the primary header, cut the entry array short.
        let src = MemSource::new(disk[..2 * 512 + 1024].to_vec());
        assert!(matches!(read(&src), Err(Error::Corrupt(_))));
    }

    #[test]
    fn partition_past_the_end_is_dropped_into_damage() {
        let disk = build(
            512,
            2048,
            &[
                spec(Guid::HFS_PLUS, 40, 99, "ok"),
                spec(Guid::LINUX_DATA, 5000, 6000, "gone"),
            ],
        );
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 1);
        assert_eq!(map.damage.len(), 1);
        assert!(map.damage[0].to_string().contains("partition start"));
    }

    #[test]
    fn inverted_and_overflowing_entries_are_damage() {
        let disk = build(
            512,
            2048,
            &[
                spec(Guid::HFS_PLUS, 100, 50, "inverted"),
                spec(Guid::HFS_PLUS, u64::MAX - 1, u64::MAX, "huge"),
                spec(Guid::HFS_PLUS, 0, u64::MAX, "all"),
                spec(Guid::HFS_PLUS, 40, 99, "ok"),
            ],
        );
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 1);
        assert_eq!(map.partitions[0].number, 4);
        assert_eq!(map.damage.len(), 3);
    }

    #[test]
    fn entry_array_bound_is_enforced() {
        // 1 << 20 entries of 128 bytes is 128 MiB. Re-sign the header so only
        // the bound can fail.
        let mut disk = good_disk();
        for base in [512usize, 2047 * 512] {
            disk[base + 80..base + 84].copy_from_slice(&(1u32 << 20).to_le_bytes());
            disk[base + 16..base + 20].fill(0);
            let crc = crc32(&disk[base..base + 92]);
            disk[base + 16..base + 20].copy_from_slice(&crc.to_le_bytes());
        }
        match read(&MemSource::new(disk)) {
            Err(Error::Corrupt(c)) => {
                assert!(matches!(c.kind, CorruptKind::LimitExceeded { .. }), "{c}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bad_entry_size_is_error() {
        let mut disk = good_disk();
        for base in [512usize, 2047 * 512] {
            disk[base + 84..base + 88].copy_from_slice(&100u32.to_le_bytes());
            disk[base + 16..base + 20].fill(0);
            let crc = crc32(&disk[base..base + 92]);
            disk[base + 16..base + 20].copy_from_slice(&crc.to_le_bytes());
        }
        assert!(matches!(
            read(&MemSource::new(disk)),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn name_decoding_stops_at_nul_and_replaces_bad_surrogates() {
        let mut disk = good_disk();
        // Entry 0 name: 'A', lone high surrogate, 'B', NUL, 'C' (ignored).
        let units = [0x41u16, 0xD800, 0x42, 0, 0x43];
        for (j, u) in units.iter().enumerate() {
            disk[1024 + 56 + j * 2..1024 + 58 + j * 2].copy_from_slice(&u.to_le_bytes());
        }
        // Re-sign both arrays and headers by rebuilding the CRCs.
        let array_len = 128 * 128;
        let array = disk[1024..1024 + array_len].to_vec();
        let crc = crc32(&array);
        let backup_array = (2047 - 32) * 512;
        disk[backup_array..backup_array + array_len].copy_from_slice(&array);
        for base in [512usize, 2047 * 512] {
            disk[base + 88..base + 92].copy_from_slice(&crc.to_le_bytes());
            disk[base + 16..base + 20].fill(0);
            let h = crc32(&disk[base..base + 92]);
            disk[base + 16..base + 20].copy_from_slice(&h.to_le_bytes());
        }
        let map = read(&MemSource::new(disk)).unwrap().unwrap();
        assert_eq!(map.partitions[0].name.as_deref(), Some("A\u{FFFD}B"));
        assert!(map.damage.is_empty());
    }

    #[test]
    fn sector_4096_disk_is_read_with_its_own_size() {
        let disk = build(
            4096,
            256,
            &[
                spec(Guid::APFS, 6, 100, "apfs"),
                spec(Guid::LINUX_DATA, 101, 200, "linux"),
            ],
        );
        let src = MemSource::with_sector_size(disk.clone(), 4096);
        let map = read(&src).unwrap().unwrap();
        assert_eq!(map.block_size, 4096);
        assert_eq!(map.partitions[0].start, 6 * 4096);
        assert_eq!(map.partitions[0].hint, TypeHint::Apfs);
        // A source that wrongly reports 512 finds nothing at 512...
        let wrong = MemSource::new(disk);
        assert!(read(&wrong).unwrap().is_none());
        // ...but the explicit sector size finds it.
        let map = read_with_sector_size(&wrong, 4096).unwrap().unwrap();
        assert_eq!(map.block_size, 4096);
    }

    #[test]
    fn invalid_sector_size_is_none() {
        let src = MemSource::new(good_disk());
        assert!(read_with_sector_size(&src, 100).unwrap().is_none());
        assert!(read_with_sector_size(&src, 0).unwrap().is_none());
    }
}
