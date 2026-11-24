// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Master Boot Record reader, including extended partitions.
//!
//! The MBR has no magic beyond `55 AA`, which every FAT and NTFS boot sector
//! also carries. [`read`] therefore also rejects sectors whose partition
//! entries are not plausible, so a bare volume is not mistaken for a map.

use std::collections::HashSet;

use atlas_fs_core::error::{CorruptKind, Corruption, Location, Result};
use atlas_fs_core::io::block::BlockSource;

use super::{Partition, PartitionMap, PartitionType, Scheme, TypeHint};

const STRUCTURE: &str = "MBR";
const EBR_STRUCTURE: &str = "MBR extended boot record";
const SECTOR: usize = 512;
const TABLE_OFFSET: usize = 446;
const ENTRY_SIZE: usize = 16;
/// Most extended boot records followed across all extended partitions, and
/// so the most logical partitions.
const MAX_LOGICAL: usize = 128;

/// One raw partition table entry.
#[derive(Clone, Copy)]
struct Entry {
    boot: u8,
    kind: u8,
    lba: u32,
    sectors: u32,
}

impl Entry {
    fn is_extended(&self) -> bool {
        matches!(self.kind, 0x05 | 0x0F | 0x85)
    }
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(buf.get(at..end)?.try_into().ok()?))
}

/// Reads the four entries of a sector with a `55 AA` signature.
/// `None` when the signature is missing.
fn entries(sector: &[u8]) -> Option<[Entry; 4]> {
    if sector.get(510..512)? != [0x55, 0xAA] {
        return None;
    }
    let mut out = [Entry {
        boot: 0,
        kind: 0,
        lba: 0,
        sectors: 0,
    }; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = i
            .checked_mul(ENTRY_SIZE)
            .and_then(|o| o.checked_add(TABLE_OFFSET))?;
        let raw = sector.get(at..at.checked_add(ENTRY_SIZE)?)?;
        *slot = Entry {
            boot: *raw.first()?,
            kind: *raw.get(4)?,
            lba: le_u32(raw, 8)?,
            sectors: le_u32(raw, 12)?,
        };
    }
    Some(out)
}

/// Reads the 512 bytes at `lba`. `None` when they are outside the source.
fn read_sector(source: &dyn BlockSource, lba: u64, ss: u64) -> Result<Option<[u8; SECTOR]>> {
    let Some(offset) = lba.checked_mul(ss) else {
        return Ok(None);
    };
    match offset.checked_add(SECTOR as u64) {
        Some(end) if end <= source.len() => {}
        _ => return Ok(None),
    }
    let mut buf = [0u8; SECTOR];
    source.read_at(offset, &mut buf)?;
    Ok(Some(buf))
}

/// Reads the MBR at sector 0. `Ok(None)` when it is not one.
///
/// Not an MBR: no `55 AA`, a boot flag other than `0x00` or `0x80`, a used
/// entry of zero length, or four empty entries. The `0xEE` entries of a
/// protective MBR are kept in the map; the dispatcher looks at them.
pub fn read(source: &dyn BlockSource) -> Result<Option<PartitionMap>> {
    let ss_u32 = source.sector_size();
    let ss = u64::from(ss_u32);
    let Some(sector) = read_sector(source, 0, ss)? else {
        return Ok(None);
    };
    let Some(table) = entries(&sector) else {
        return Ok(None);
    };
    if table
        .iter()
        .any(|e| !matches!(e.boot, 0x00 | 0x80) || (e.kind != 0 && e.sectors == 0))
        || table.iter().all(|e| e.kind == 0)
    {
        return Ok(None);
    }

    let source_len = source.len();
    let mut partitions = Vec::new();
    let mut damage = Vec::new();
    let mut extended = Vec::new();

    for (index, e) in table.iter().enumerate() {
        if e.kind == 0 {
            continue;
        }
        if e.is_extended() {
            extended.push(u64::from(e.lba));
            continue;
        }
        let number = u32::try_from(index).unwrap_or(0).saturating_add(1);
        let entry_at = Location::Byte(
            u64::try_from(index)
                .unwrap_or(0)
                .saturating_mul(ENTRY_SIZE as u64)
                .saturating_add(TABLE_OFFSET as u64),
        );
        match make(number, u64::from(e.lba), e.sectors, e.kind, ss, source_len) {
            Ok(p) => partitions.push(p),
            Err(kind) => damage.push(Corruption::new(STRUCTURE, entry_at, kind)),
        }
    }

    // Logical partitions, numbered from 5 across all extended partitions.
    let mut visited = HashSet::new();
    let mut logical = 0usize;
    'chains: for ext_start in extended {
        let mut ebr_lba = ext_start;
        loop {
            let at = Location::Byte(ebr_lba.saturating_mul(ss));
            if !visited.insert(ebr_lba) {
                damage.push(Corruption::new(
                    EBR_STRUCTURE,
                    at,
                    CorruptKind::Loop { what: "EBR chain" },
                ));
                continue 'chains;
            }
            // Bound the EBRs visited, not the partitions found: a chain of
            // empty EBRs with valid links would otherwise walk the whole disk.
            if visited.len() > MAX_LOGICAL {
                damage.push(Corruption::new(
                    EBR_STRUCTURE,
                    at,
                    CorruptKind::LimitExceeded {
                        what: "logical partitions",
                        limit: MAX_LOGICAL as u64,
                    },
                ));
                break 'chains;
            }
            let sector = match read_sector(source, ebr_lba, ss)? {
                Some(s) => s,
                None => {
                    damage.push(Corruption::new(
                        EBR_STRUCTURE,
                        at,
                        CorruptKind::OutOfRange {
                            field: "EBR location",
                            value: ebr_lba.saturating_mul(ss),
                            limit_name: "source size",
                            limit: source_len,
                        },
                    ));
                    continue 'chains;
                }
            };
            let Some(ebr) = entries(&sector) else {
                damage.push(Corruption::new(
                    EBR_STRUCTURE,
                    at,
                    CorruptKind::BadSignature {
                        expected: 0xAA55,
                        found: u64::from(u16::from_le_bytes([
                            sector.get(510).copied().unwrap_or(0),
                            sector.get(511).copied().unwrap_or(0),
                        ])),
                    },
                ));
                continue 'chains;
            };
            let (first, link) = (ebr[0], ebr[1]);
            if first.kind != 0 && first.sectors != 0 {
                let number = u32::try_from(logical).unwrap_or(u32::MAX).saturating_add(5);
                let start = ebr_lba.checked_add(u64::from(first.lba));
                let made = start
                    .ok_or(CorruptKind::Overflow {
                        field: "logical partition start",
                    })
                    .and_then(|s| make(number, s, first.sectors, first.kind, ss, source_len));
                match made {
                    Ok(p) => {
                        partitions.push(p);
                        logical = logical.saturating_add(1);
                    }
                    Err(kind) => damage.push(Corruption::new(EBR_STRUCTURE, at, kind)),
                }
            }
            if !link.is_extended() {
                continue 'chains;
            }
            match ext_start.checked_add(u64::from(link.lba)) {
                Some(next) => ebr_lba = next,
                None => {
                    damage.push(Corruption::new(
                        EBR_STRUCTURE,
                        at,
                        CorruptKind::Overflow { field: "next EBR" },
                    ));
                    continue 'chains;
                }
            }
        }
    }

    Ok(Some(PartitionMap {
        scheme: Scheme::Mbr,
        block_size: ss_u32,
        partitions,
        damage,
    }))
}

/// Builds a partition from sector counts, clamping to the source.
fn make(
    number: u32,
    start_lba: u64,
    sectors: u32,
    kind: u8,
    ss: u64,
    source_len: u64,
) -> std::result::Result<Partition, CorruptKind> {
    let start = start_lba
        .checked_mul(ss)
        .ok_or(CorruptKind::Overflow { field: "start LBA" })?;
    let len = u64::from(sectors)
        .checked_mul(ss)
        .ok_or(CorruptKind::Overflow {
            field: "sector count",
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
    Ok(Partition {
        number,
        start,
        len,
        truncated,
        kind: PartitionType::Mbr(kind),
        hint: hint(kind),
        name: None,
    })
}

fn hint(kind: u8) -> TypeHint {
    match kind {
        0xAF => TypeHint::Hfs,
        0x01 | 0x04 | 0x06 | 0x07 | 0x0B | 0x0C | 0x0E => TypeHint::Microsoft,
        0xEF => TypeHint::EfiSystem,
        0x83 => TypeHint::Linux,
        _ => TypeHint::Other,
    }
}

/// Fixture helpers shared with the dispatcher tests.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(missing_docs)]
pub mod testutil {
    /// Writes one partition table entry and the `55 AA` signature.
    pub fn put(sector: &mut [u8], slot: usize, boot: u8, kind: u8, lba: u32, sectors: u32) {
        let at = 446 + slot * 16;
        sector[at] = boot;
        sector[at + 4] = kind;
        sector[at + 8..at + 12].copy_from_slice(&lba.to_le_bytes());
        sector[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
        sector[510] = 0x55;
        sector[511] = 0xAA;
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::put;
    use super::*;
    use atlas_fs_core::error::Error;
    use atlas_fs_core::io::block::MemSource;

    /// 1 MiB (2048 sectors) with the given sector 0.
    fn disk(sector0: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 2048 * 512];
        d[..512].copy_from_slice(sector0);
        d
    }

    #[test]
    fn good_primary_map() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0x80, 0xAF, 64, 512);
        put(&mut s, 1, 0x00, 0x0C, 600, 100);
        put(&mut s, 2, 0x00, 0x83, 700, 100);
        put(&mut s, 3, 0x00, 0x42, 800, 100);
        let map = read(&MemSource::new(disk(&s))).unwrap().unwrap();
        assert_eq!(map.scheme, Scheme::Mbr);
        assert_eq!(map.block_size, 512);
        assert!(map.damage.is_empty());
        assert_eq!(map.partitions.len(), 4);
        assert_eq!(map.partitions[0].start, 64 * 512);
        assert_eq!(map.partitions[0].len, 512 * 512);
        assert_eq!(map.partitions[0].hint, TypeHint::Hfs);
        assert_eq!(map.partitions[0].kind, PartitionType::Mbr(0xAF));
        assert_eq!(map.partitions[1].hint, TypeHint::Microsoft);
        assert_eq!(map.partitions[2].hint, TypeHint::Linux);
        assert_eq!(map.partitions[3].hint, TypeHint::Other);
        assert_eq!(map.partitions[3].number, 4);
        assert!(map.partitions.iter().all(|p| p.name.is_none()));
    }

    #[test]
    fn unused_slots_are_skipped_but_numbers_keep_slot() {
        let mut s = [0u8; 512];
        put(&mut s, 2, 0, 0xEF, 64, 100);
        let map = read(&MemSource::new(disk(&s))).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 1);
        assert_eq!(map.partitions[0].number, 3);
        assert_eq!(map.partitions[0].hint, TypeHint::EfiSystem);
    }

    #[test]
    fn not_an_mbr() {
        // No signature.
        assert!(read(&MemSource::new(vec![0u8; 4096])).unwrap().is_none());
        // Signature but nothing in the table.
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        assert!(read(&MemSource::new(disk(&s))).unwrap().is_none());
        // Bad boot flag, as in a FAT boot sector (0x29 extended boot signature).
        let mut s = [0u8; 512];
        put(&mut s, 0, 0x00, 0x83, 64, 100);
        s[446 + 16] = 0x29;
        assert!(read(&MemSource::new(disk(&s))).unwrap().is_none());
        // Used entry of zero length.
        let mut s = [0u8; 512];
        put(&mut s, 0, 0x00, 0x83, 64, 100);
        put(&mut s, 1, 0x00, 0x07, 64, 0);
        assert!(read(&MemSource::new(disk(&s))).unwrap().is_none());
        // Shorter than a sector.
        assert!(read(&MemSource::new(vec![0u8; 100])).unwrap().is_none());
    }

    #[test]
    fn partition_clamped_and_partition_past_end() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x83, 2000, 1000); // runs past the 2048-sector end
        put(&mut s, 1, 0, 0x83, 5000, 10); // starts past the end
        put(&mut s, 2, 0, 0x83, 100, u32::MAX); // clamped, huge
        let map = read(&MemSource::new(disk(&s))).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 2);
        assert!(map.partitions[0].truncated);
        assert_eq!(map.partitions[0].len, 48 * 512);
        assert!(map.partitions[1].truncated);
        assert_eq!(map.partitions[1].len, (2048 - 100) * 512);
        assert_eq!(map.damage.len(), 1);
    }

    #[test]
    fn protective_entry_is_kept() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0xEE, 1, 2047);
        let map = read(&MemSource::new(disk(&s))).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 1);
        assert_eq!(map.partitions[0].kind, PartitionType::Mbr(0xEE));
        assert_eq!(map.partitions[0].hint, TypeHint::Other);
    }

    /// Writes an EBR at `lba`.
    fn ebr(d: &mut [u8], lba: usize, rel_start: u32, sectors: u32, next_rel: Option<u32>) {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x83, rel_start, sectors);
        if let Some(n) = next_rel {
            put(&mut s, 1, 0, 0x05, n, 100);
        }
        d[lba * 512..lba * 512 + 512].copy_from_slice(&s);
    }

    #[test]
    fn extended_chain_with_two_logicals() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0x80, 0xAF, 64, 100);
        put(&mut s, 1, 0, 0x0F, 200, 1000);
        let mut d = disk(&s);
        ebr(&mut d, 200, 2, 50, Some(100)); // second EBR at 200 + 100
        ebr(&mut d, 300, 2, 60, None);
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert!(map.damage.is_empty(), "{:?}", map.damage);
        let nums: Vec<_> = map.partitions.iter().map(|p| p.number).collect();
        assert_eq!(nums, [1, 5, 6]);
        assert_eq!(map.partitions[1].start, 202 * 512);
        assert_eq!(map.partitions[1].len, 50 * 512);
        assert_eq!(map.partitions[2].start, 302 * 512);
        assert_eq!(map.partitions[2].len, 60 * 512);
    }

    #[test]
    fn ebr_loop_stops_with_loop_damage() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x83, 64, 100);
        put(&mut s, 1, 0, 0x05, 200, 1000);
        let mut d = disk(&s);
        ebr(&mut d, 200, 2, 50, Some(100));
        ebr(&mut d, 300, 2, 50, Some(0)); // links back to the first EBR
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 3); // primary + two logicals
        assert_eq!(map.damage.len(), 1);
        assert!(matches!(map.damage[0].kind, CorruptKind::Loop { .. }));
    }

    #[test]
    fn ebr_self_loop() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x05, 200, 1000);
        let mut d = disk(&s);
        ebr(&mut d, 200, 2, 50, Some(0));
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 1);
        assert!(matches!(map.damage[0].kind, CorruptKind::Loop { .. }));
    }

    #[test]
    fn bad_ebr_signature_stops_chain_and_keeps_primaries() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x83, 64, 100);
        put(&mut s, 1, 0, 0x05, 200, 1000);
        let mut d = disk(&s);
        ebr(&mut d, 200, 2, 50, Some(100));
        // EBR at 300 is all zeros: no signature.
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 2);
        assert!(matches!(
            map.damage[0].kind,
            CorruptKind::BadSignature { .. }
        ));
    }

    #[test]
    fn ebr_past_end_of_source_is_damage() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x05, 5000, 1000);
        let map = read(&MemSource::new(disk(&s))).unwrap().unwrap();
        assert!(map.partitions.is_empty());
        assert_eq!(map.damage.len(), 1);
    }

    #[test]
    fn logical_partition_limit() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x05, 10, 2000);
        // 130 EBRs, one sector apart, chained from the extended start.
        let mut d = vec![0u8; 400 * 512];
        d[..512].copy_from_slice(&s);
        for i in 0..130u32 {
            let next = (i < 129).then_some(i + 1);
            ebr(&mut d, 10 + i as usize, 1, 1, next);
        }
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert_eq!(map.partitions.len(), 128);
        assert_eq!(map.partitions.last().unwrap().number, 132);
        assert!(matches!(
            map.damage.last().unwrap().kind,
            CorruptKind::LimitExceeded { .. }
        ));
    }

    #[test]
    fn chain_of_empty_ebrs_is_bounded() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0x05, 10, 2000);
        // 300 linked EBRs whose first entry is empty: no logical partition is
        // ever found, so only the EBR bound can stop the walk.
        let mut d = vec![0u8; 400 * 512];
        d[..512].copy_from_slice(&s);
        for i in 0..300u32 {
            let mut e = [0u8; 512];
            put(&mut e, 1, 0, 0x05, i + 1, 1);
            let at = (10 + i as usize) * 512;
            d[at..at + 512].copy_from_slice(&e);
        }
        let map = read(&MemSource::new(d)).unwrap().unwrap();
        assert!(map.partitions.is_empty());
        assert!(matches!(
            map.damage.last().unwrap().kind,
            CorruptKind::LimitExceeded { .. }
        ));
    }

    #[test]
    fn io_error_propagates() {
        struct Failing;
        impl BlockSource for Failing {
            fn len(&self) -> u64 {
                4096
            }
            fn sector_size(&self) -> u32 {
                512
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                Err(Error::OutOfBounds {
                    offset,
                    len: buf.len() as u64,
                    size: 0,
                })
            }
        }
        assert!(read(&Failing).is_err());
    }

    #[test]
    fn four_kib_sectors_use_the_source_sector_size() {
        let mut s = [0u8; 512];
        put(&mut s, 0, 0, 0xAF, 4, 10);
        let mut d = vec![0u8; 64 * 4096];
        d[..512].copy_from_slice(&s);
        let map = read(&MemSource::with_sector_size(d, 4096))
            .unwrap()
            .unwrap();
        assert_eq!(map.block_size, 4096);
        assert_eq!(map.partitions[0].start, 4 * 4096);
        assert_eq!(map.partitions[0].len, 10 * 4096);
    }
}
