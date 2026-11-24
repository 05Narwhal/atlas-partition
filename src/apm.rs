// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Apple Partition Map reader. Everything is big-endian.
//!
//! Block 0 is the driver descriptor (`ER`); the map entries (`PM`) start at
//! block 1, one per block, each repeating the total entry count.
//!
//! The block size is the unit of both the entry stride and the start and
//! length fields. The `ER` block states one, but optical-disc images often
//! state 2048 there and then lay the entries out 512 bytes apart. The reader
//! therefore tests each candidate unit by walking the whole chain of `PM`
//! entries it implies, not just the one at block 1: a 512-byte map with four
//! or more entries has a `PM` at byte 2048 as well (its fourth entry), and
//! only the chain walk tells that apart from a real 2048-byte map.

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::BlockSource;

use super::{Partition, PartitionMap, PartitionType, Scheme, TypeHint};

const STRUCTURE: &str = "Apple Partition Map";
const ER_SIGNATURE: u16 = 0x4552;
const PM_SIGNATURE: u16 = 0x504D;
/// Bytes of an entry this reader uses (through the type string).
const ENTRY_BYTES: u64 = 80;
/// Most entries read from one map.
const MAX_ENTRIES: u32 = 256;

fn be_u16(buf: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_be_bytes(buf.get(at..end)?.try_into().ok()?))
}

fn be_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_be_bytes(buf.get(at..end)?.try_into().ok()?))
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

/// The map entry at `index` for a given unit. `None` when it lies outside the
/// source or does not carry `PM`.
fn read_entry(source: &dyn BlockSource, unit: u32, index: u32) -> Result<Option<Vec<u8>>> {
    let Some(offset) = u64::from(unit).checked_mul(u64::from(index)) else {
        return Ok(None);
    };
    let entry = read_bytes(source, offset, ENTRY_BYTES)?;
    Ok(entry.filter(|e| be_u16(e, 0) == Some(PM_SIGNATURE)))
}

/// How well a unit explains the map.
struct Chain {
    /// Consecutive `PM` entries found from block 1, at most `MAX_ENTRIES`.
    length: u32,
    /// The chain is as long as the first entry's count says.
    complete: bool,
}

fn walk(source: &dyn BlockSource, unit: u32) -> Result<Chain> {
    let none = Chain {
        length: 0,
        complete: false,
    };
    let Some(first) = read_entry(source, unit, 1)? else {
        return Ok(none);
    };
    let target = be_u32(&first, 4).unwrap_or(0).clamp(1, MAX_ENTRIES);
    let mut length = 1u32;
    while length < target {
        let next = length.saturating_add(1);
        if read_entry(source, unit, next)?.is_none() {
            break;
        }
        length = next;
    }
    Ok(Chain {
        length,
        complete: length == target,
    })
}

/// Chooses the block size, or `None` when no unit finds a map.
fn pick_unit(source: &dyn BlockSource) -> Result<Option<u32>> {
    let candidates: Vec<u32> = match read_bytes(source, 0, 4)? {
        Some(b0) if be_u16(&b0, 0) == Some(ER_SIGNATURE) => {
            let bs = u32::from(be_u16(&b0, 2).unwrap_or(0));
            if bs.is_power_of_two() && (512..=4096).contains(&bs) {
                if bs == 512 { vec![512] } else { vec![bs, 512] }
            } else {
                vec![512, 2048]
            }
        }
        _ => vec![512, 2048],
    };
    let mut best: Option<(u32, u32)> = None;
    for unit in candidates {
        let chain = walk(source, unit)?;
        if chain.complete {
            return Ok(Some(unit));
        }
        if chain.length > best.map_or(0, |(_, l)| l) {
            best = Some((unit, chain.length));
        }
    }
    Ok(best.map(|(unit, _)| unit))
}

/// Reads the Apple Partition Map. `Ok(None)` when no `PM` entry is found at
/// block 1 for any plausible block size.
pub fn read(source: &dyn BlockSource) -> Result<Option<PartitionMap>> {
    let Some(unit) = pick_unit(source)? else {
        return Ok(None);
    };
    let unit64 = u64::from(unit);
    let source_len = source.len();

    let first = read_entry(source, unit, 1)?.ok_or(Error::Corrupt(Corruption::new(
        STRUCTURE,
        Location::Byte(unit64),
        CorruptKind::BadSignature {
            expected: u64::from(PM_SIGNATURE),
            found: 0,
        },
    )))?;
    let declared = be_u32(&first, 4).unwrap_or(0);
    if declared == 0 {
        return Err(Error::Corrupt(Corruption::new(
            STRUCTURE,
            Location::Byte(unit64),
            CorruptKind::InvalidValue {
                field: "map entry count",
                value: 0,
            },
        )));
    }

    let mut damage = Vec::new();
    let count = if declared > MAX_ENTRIES {
        damage.push(Corruption::new(
            STRUCTURE,
            Location::Byte(unit64),
            CorruptKind::LimitExceeded {
                what: "map entries",
                limit: u64::from(MAX_ENTRIES),
            },
        ));
        MAX_ENTRIES
    } else {
        declared
    };

    let mut partitions = Vec::new();
    for index in 1..=count {
        let at = Location::Byte(unit64.saturating_mul(u64::from(index)));
        let Some(entry) = read_entry(source, unit, index)? else {
            let offset = unit64.saturating_mul(u64::from(index));
            let kind = if offset.saturating_add(ENTRY_BYTES) > source_len {
                CorruptKind::Truncated {
                    needed: ENTRY_BYTES,
                    available: source_len.saturating_sub(offset),
                }
            } else {
                CorruptKind::BadSignature {
                    expected: u64::from(PM_SIGNATURE),
                    found: 0,
                }
            };
            damage.push(Corruption::new(STRUCTURE, at, kind));
            break;
        };
        match parse_entry(&entry, index, unit64, source_len) {
            Ok(Some(p)) => partitions.push(p),
            Ok(None) => {}
            Err(kind) => damage.push(Corruption::new("Apple Partition Map entry", at, kind)),
        }
    }

    Ok(Some(PartitionMap {
        scheme: Scheme::Apm,
        block_size: unit,
        partitions,
        damage,
    }))
}

/// One entry. `Ok(None)` for a zero-length entry.
fn parse_entry(
    entry: &[u8],
    index: u32,
    unit: u64,
    source_len: u64,
) -> std::result::Result<Option<Partition>, CorruptKind> {
    let short = CorruptKind::Truncated {
        needed: ENTRY_BYTES,
        available: u64::try_from(entry.len()).unwrap_or(u64::MAX),
    };
    let start_blocks = be_u32(entry, 8).ok_or_else(|| short.clone())?;
    let count_blocks = be_u32(entry, 12).ok_or_else(|| short.clone())?;
    if count_blocks == 0 {
        return Ok(None);
    }
    let name = text(entry.get(16..48).ok_or_else(|| short.clone())?);
    let kind = text(entry.get(48..80).ok_or(short)?);

    let start = u64::from(start_blocks)
        .checked_mul(unit)
        .ok_or(CorruptKind::Overflow {
            field: "physical start block",
        })?;
    let len = u64::from(count_blocks)
        .checked_mul(unit)
        .ok_or(CorruptKind::Overflow {
            field: "block count",
        })?;
    if start >= source_len {
        return Err(CorruptKind::OutOfRange {
            field: "partition start",
            value: start,
            limit_name: "source size",
            limit: source_len,
        });
    }
    let room = source_len.saturating_sub(start);
    let (len, truncated) = if len > room {
        (room, true)
    } else {
        (len, false)
    };
    let hint = hint(&kind);
    Ok(Some(Partition {
        number: index,
        start,
        len,
        truncated,
        kind: PartitionType::Apm(kind),
        hint,
        name: Some(name),
    }))
}

/// Bytes up to the first NUL; anything that is not ASCII becomes U+FFFD.
fn text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

fn hint(kind: &str) -> TypeHint {
    match kind {
        "Apple_HFS" | "Apple_HFSX" => TypeHint::Hfs,
        "Apple_APFS" => TypeHint::Apfs,
        "Apple_CoreStorage" => TypeHint::CoreStorage,
        "Apple_partition_map"
        | "Apple_Free"
        | "Apple_Void"
        | "Apple_Patches"
        | "Apple_FWDriver" => TypeHint::NotData,
        k if k.starts_with("Apple_Driver") => TypeHint::NotData,
        k if k.starts_with("DOS_FAT_") || k.starts_with("Windows_FAT_") => TypeHint::Microsoft,
        k if k.starts_with("Linux") => TypeHint::Linux,
        _ => TypeHint::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_fs_core::io::block::MemSource;

    /// (start block, block count, name, type)
    type Spec = (u32, u32, &'static str, &'static str);

    /// Builds a map. `er_block_size` goes in block 0 (`None` omits `ER`);
    /// `stride` is the byte distance between entries; `declared` overrides
    /// the entry count written into every entry.
    fn build(
        total: usize,
        er_block_size: Option<u16>,
        stride: usize,
        declared: Option<u32>,
        specs: &[Spec],
    ) -> Vec<u8> {
        let mut d = vec![0u8; total];
        if let Some(bs) = er_block_size {
            d[..2].copy_from_slice(b"ER");
            d[2..4].copy_from_slice(&bs.to_be_bytes());
        }
        for (i, (start, count, name, kind)) in specs.iter().enumerate() {
            let at = (i + 1) * stride;
            if at + 80 > total {
                break;
            }
            let e = &mut d[at..at + 80];
            e[..2].copy_from_slice(b"PM");
            let n = declared.unwrap_or(specs.len() as u32);
            e[4..8].copy_from_slice(&n.to_be_bytes());
            e[8..12].copy_from_slice(&start.to_be_bytes());
            e[12..16].copy_from_slice(&count.to_be_bytes());
            e[16..16 + name.len()].copy_from_slice(name.as_bytes());
            e[48..48 + kind.len()].copy_from_slice(kind.as_bytes());
        }
        d
    }

    const MAP512: [Spec; 5] = [
        (1, 63, "Apple", "Apple_partition_map"),
        (64, 32, "Macintosh", "Apple_Driver43"),
        (96, 1000, "Macintosh HD", "Apple_HFS"),
        (1096, 900, "Windows", "DOS_FAT_32"),
        (1996, 52, "", "Apple_Free"),
    ];

    #[test]
    fn good_512_map() {
        let d = build(1 << 20, Some(512), 512, None, &MAP512);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.scheme, Scheme::Apm);
        assert_eq!(map.block_size, 512);
        assert!(map.damage.is_empty(), "{:?}", map.damage);
        assert_eq!(map.partitions.len(), 5);
        let hfs = &map.partitions[2];
        assert_eq!(hfs.number, 3);
        assert_eq!(hfs.start, 96 * 512);
        assert_eq!(hfs.len, 1000 * 512);
        assert_eq!(hfs.hint, TypeHint::Hfs);
        assert_eq!(hfs.kind, PartitionType::Apm("Apple_HFS".into()));
        assert_eq!(hfs.name.as_deref(), Some("Macintosh HD"));
        assert_eq!(map.partitions[3].hint, TypeHint::Microsoft);
    }

    #[test]
    fn not_data_entries_are_listed() {
        let d = build(1 << 20, Some(512), 512, None, &MAP512);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        let hints: Vec<_> = map.partitions.iter().map(|p| p.hint).collect();
        assert_eq!(hints[0], TypeHint::NotData); // the map itself
        assert_eq!(hints[1], TypeHint::NotData); // driver
        assert_eq!(hints[4], TypeHint::NotData); // free
    }

    #[test]
    fn er_2048_with_512_byte_entries_uses_512() {
        // Five entries: the fourth sits at byte 2048, where a naive reader
        // looking at the ER block size finds a "PM" and stops.
        let d = build(1 << 20, Some(2048), 512, None, &MAP512);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.block_size, 512);
        assert_eq!(map.partitions.len(), 5);
        assert_eq!(map.partitions[2].start, 96 * 512);
        assert!(map.damage.is_empty());
    }

    #[test]
    fn real_2048_map() {
        let specs: [Spec; 3] = [
            (1, 3, "Apple", "Apple_partition_map"),
            (4, 100, "CD", "Apple_HFS"),
            (104, 50, "", "Apple_Free"),
        ];
        let d = build(1 << 20, Some(2048), 2048, None, &specs);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.block_size, 2048);
        assert_eq!(map.partitions.len(), 3);
        assert_eq!(map.partitions[1].start, 4 * 2048);
        assert_eq!(map.partitions[1].len, 100 * 2048);
    }

    #[test]
    fn missing_or_invalid_er_tries_512_then_2048() {
        let d = build(1 << 20, None, 512, None, &MAP512);
        assert_eq!(read(&MemSource::new(d)).unwrap().unwrap().block_size, 512);
        let d = build(1 << 20, Some(1000), 512, None, &MAP512);
        assert_eq!(read(&MemSource::new(d)).unwrap().unwrap().block_size, 512);
        let specs: [Spec; 2] = [
            (1, 3, "A", "Apple_partition_map"),
            (4, 100, "B", "Apple_HFS"),
        ];
        let d = build(1 << 20, None, 2048, None, &specs);
        assert_eq!(read(&MemSource::new(d)).unwrap().unwrap().block_size, 2048);
    }

    #[test]
    fn absent_signature_is_none() {
        assert!(read(&MemSource::new(vec![0u8; 1 << 20])).unwrap().is_none());
        assert!(read(&MemSource::new(vec![0u8; 100])).unwrap().is_none());
        // ER but no PM anywhere.
        let d = build(1 << 20, Some(512), 512, None, &[]);
        assert!(read(&MemSource::new(d)).unwrap().is_none());
    }

    #[test]
    fn bad_signature_mid_map_is_damage() {
        let mut d = build(1 << 20, Some(512), 512, None, &MAP512);
        d[3 * 512] = 0; // entry 3 loses "PM"
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 2);
        assert_eq!(map.damage.len(), 1);
        assert!(matches!(
            map.damage[0].kind,
            CorruptKind::BadSignature { .. }
        ));
    }

    #[test]
    fn entry_count_past_bound_is_damage_and_capped() {
        let d = build(1 << 20, Some(512), 512, Some(300), &MAP512[..3]);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 3);
        assert!(
            map.damage
                .iter()
                .any(|c| matches!(c.kind, CorruptKind::LimitExceeded { .. }))
        );
    }

    #[test]
    fn zero_entry_count_is_error() {
        let d = build(1 << 20, Some(512), 512, Some(0), &MAP512);
        assert!(matches!(read(&MemSource::new(d)), Err(Error::Corrupt(_))));
    }

    #[test]
    fn truncated_source_stops_the_map() {
        // The source ends after entry 3's header; entries 4 and 5 are missing.
        let d = build(1 << 20, Some(512), 512, None, &MAP512);
        let map = read(&MemSource::new(d[..3 * 512 + 100].to_vec()))
            .unwrap()
            .unwrap();
        // Entry 3 starts at block 96, past the 1636-byte source: dropped.
        assert_eq!(map.partitions.len(), 1);
        assert!(
            map.damage
                .iter()
                .any(|c| matches!(c.kind, CorruptKind::Truncated { .. }))
        );
    }

    #[test]
    fn partition_clamped_and_partition_past_end() {
        let specs: [Spec; 3] = [
            (1, 3, "map", "Apple_partition_map"),
            (100, 5000, "big", "Apple_HFS"), // 1 MiB = 2048 blocks
            (4000, 10, "gone", "Apple_HFS"),
        ];
        let d = build(1 << 20, Some(512), 512, None, &specs);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 2);
        let big = &map.partitions[1];
        assert!(big.truncated);
        assert_eq!(big.len, (2048 - 100) * 512);
        assert_eq!(map.damage.len(), 1);
    }

    #[test]
    fn huge_block_count_is_clamped() {
        // 0xFFFFFFFF blocks fit in u64 bytes and must be clamped, not wrapped.
        let specs: [Spec; 2] = [
            (1, 3, "map", "Apple_partition_map"),
            (2, u32::MAX, "huge", "Apple_HFS"),
        ];
        let d = build(1 << 20, Some(512), 512, None, &specs);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert!(map.partitions[1].truncated);
    }

    #[test]
    fn names_and_types_decode_ascii_only() {
        let mut d = build(1 << 20, Some(512), 512, None, &MAP512[..3]);
        d[512 + 16] = b'A';
        d[512 + 17] = 0x8E; // Mac Roman e-acute, not ASCII
        d[512 + 18] = b'B';
        d[512 + 19] = 0;
        d[512 + 20] = b'C'; // after the NUL: ignored
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions[0].name.as_deref(), Some("A\u{FFFD}B"));
    }

    #[test]
    fn hints() {
        assert_eq!(hint("Apple_HFSX"), TypeHint::Hfs);
        assert_eq!(hint("Apple_APFS"), TypeHint::Apfs);
        assert_eq!(hint("Apple_CoreStorage"), TypeHint::CoreStorage);
        assert_eq!(hint("Apple_Driver_ATA"), TypeHint::NotData);
        assert_eq!(hint("Apple_FWDriver"), TypeHint::NotData);
        assert_eq!(hint("Apple_Patches"), TypeHint::NotData);
        assert_eq!(hint("Apple_Void"), TypeHint::NotData);
        assert_eq!(hint("Windows_FAT_16"), TypeHint::Microsoft);
        assert_eq!(hint("Linux_swap"), TypeHint::Linux);
        assert_eq!(hint("Apple_UNIX_SVR2"), TypeHint::Other);
    }
}
