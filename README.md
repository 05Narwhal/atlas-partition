# atlas-partition

Reads the three partition tables a disk can carry: GPT (with the backup header as a fallback), MBR (with extended partitions and protective-MBR detection) and the Apple Partition Map. Each partition comes back as a slice of the disk's `BlockSource`, with a type hint, and damage the reader could work around is listed in `PartitionMap::damage`.

- GPT, MBR (primary and extended) and APM readers behind one `read(source)` call.
- Partitions come back as bounded `Slice`s of the underlying `BlockSource`.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
