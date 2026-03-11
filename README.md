# Apollo Domain Filesystem Reader

A read-only filesystem reader for Apollo Domain/OS (Aegis) disk images, reverse-engineered from a 2 GB disk image taken off an HP 9000 Series 400 Apollo workstation.

The on-disk format was figured out from the image itself with help from the [*AEGIS Internals and Data Structures*](https://bitsavers.org/pdf/apollo/AEGIS_Internals_and_Data_Structures_Jan86.pdf) manual (Apollo Computer Inc., January 1986, Software Release 9.0). The document describes the SR9.0 kernel's 1 KB block format; this disk uses the later 4 KB block variant introduced around SR10, so field offsets and sizes were adjusted empirically.

**Author's Note:** In the interest of transparency, I want to point out that a good chunk of this code was written by throwing Claude Opus at the problem after sourcing the Aegis Internals documentation. I used this creation to read files purely for curiosity's sake off an image of the Apollo's disk, and it was good enough for that at least. The usual caveats and disclaimers around accuracy and safety apply when trying to do anything around working with data using no-warranty open source tools off the internet.

## Requirements

Python 3.9+ (no dependencies).

## Quick start

```
# Interactive shell (recommended)
python apollo_fs.py apollo.img

# One-shot commands
python apollo_fs.py apollo.img ls /
python apollo_fs.py apollo.img cat /etc/services
python apollo_fs.py apollo.img tree /etc 1
python apollo_fs.py apollo.img extract /etc/passwd passwd.txt
```

## Interactive shell

Run with just the image path to drop into a shell:

```
$ python apollo_fs.py apollo.img
Apollo filesystem shell — image: apollo.img
Type 'help' for commands, 'quit' to exit.

apollofs:/> ls
Directory: /
Type   Name                             UID / Target
------------------------------------------------------------------------
OBJ    bsd4.3                           [c1cb1c4a.4004ab6d]
LINK   bin                              -> $(SYSTYPE)/bin
OBJ    etc                              [c1cb1b9e.a004ab6d]
OBJ    earl                             [c2e5b920.5004ab6d]
OBJ    trillium                         [c1ea7e37.c004ab6d]
...
68 entries

apollofs:/> cd etc
apollofs:/etc> cat services
# /etc/services (DOMAIN/OS version SR10.2)
...

apollofs:/etc> cd ..
apollofs:/> find *.c /usr
apollofs:/> quit
```

### Shell commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands and usage examples |
| `pwd` | Print current directory |
| `cd <path>` | Change directory (`/` for root, `//` for network root, `..` for parent) |
| `ls [path]` | List directory contents (default: current directory) |
| `tree [path] [depth]` | Recursive directory tree (default depth: 2) |
| `find <pattern> [path]` | Search by name; supports glob patterns (`*`, `?`, `[]`) |
| `stat <path>` | Show object metadata (UID, size, timestamps, parent, page map) |
| `cat <path>` | Print file contents to stdout |
| `extract <path> <out>` | Save file contents to a local file |
| `analyze` | Show filesystem metadata (LV label, BAT, VTOC, special objects) |
| `quit` / `exit` | Exit the shell |

Paths are relative to the current directory unless they start with `/`. Absolute paths and `..` work as expected.

## One-shot commands

Every shell command also works as a CLI argument for scripting:

```bash
python apollo_fs.py apollo.img analyze
python apollo_fs.py apollo.img ls /etc
python apollo_fs.py apollo.img tree / 3
python apollo_fs.py apollo.img find "*.pas" /
python apollo_fs.py apollo.img stat /etc/passwd
python apollo_fs.py apollo.img cat /etc/hosts
python apollo_fs.py apollo.img extract /etc/services services.txt
```

`cat` output goes to stdout and VTOC index messages go to stderr, so pipes work cleanly:

```bash
python apollo_fs.py apollo.img cat /etc/services > services.txt
```

## How it works

### Disk layout

The image is a raw 512-byte-sector `dd` dump. Domain/OS organizes the disk into 4 KB blocks addressed by DADDR (disk address). Physical DADDR 0 holds the PV (Physical Volume) label; physical DADDR 1 holds the LV (Logical Volume) label; logical DADDR = physical DADDR − 1.

```
Physical DADDR 0     PV label (overwritten by Solaris VTOC on this image)
Physical DADDR 1     LV label (logical DADDR 0)
Physical DADDR 2–11  SYSBOOT area (logical DADDR 1–10)
  ...                User data
  ...                BAT (Block Availability Table) — free-space bitmap
  ...                VTOC (Volume Table of Contents) — object metadata hash table
  ...                More user data
```

### LV label

The Logical Volume label at physical DADDR 1 contains:

- Volume name and UID
- BAT location and block counts (total/free)
- VTOC indexes (VTOCXes) for four special objects: Network Root Dir, Disk Entry Dir, OS Paging File, and SYSBOOT

### VTOC

The VTOC is a hash table spread across a large extent of the disk. Each VTOC block holds a 4-byte next pointer followed by 8 VTOC Entries (VTOCEs) of 464 bytes each (the Aegis Internals document describes 232-byte VTOCEs for the 1 KB block format — the 4 KB format doubles this).

A VTOCE stores:
- Object UID (8 bytes at offset 0x08)
- File size in bytes (4 bytes at offset 0x18)
- Blocks used (4 bytes at offset 0x1C)
- Modification timestamp (4 bytes at offset 0x20, seconds since 1980-01-01)
- Parent UID (8 bytes at offset 0x40)
- Up to 32 direct page addresses (at offset 0xD4), each pointing to a 4 KB data block
- 3 file map pointers (after the page addresses) for indirect blocks, supporting larger files

A VTOCX (VTOC index) encodes the VTOC block DADDR in the upper bits and the entry index (0–7) in the lower 4 bits.

### Directories

Directories are regular objects whose data blocks contain a hash thread table starting at offset 0x80 within each block. The hash table holds 2-byte offsets pointing to entry records within the same block. Entries are chained linearly after each hash bucket.

Two entry types:
- **Object entries** (type 0x02 or 0x82): name + 8-byte UID of the target object
- **Link entries** (type 0x04): name + variable-length target path string (Domain/OS symbolic links)

Domain/OS links use special syntax: `$(SYSTYPE)` expands to the system type (e.g., `bsd4.3` or `sys5.3`), and backtick paths like `` `node_data/dev `` are relative to the node's local data directory.

### UID structure

Every object in the network has a globally unique 64-bit UID, generated by concatenating the node's unique hardware ID with a timestamp from its local clock. On this disk, most UIDs end in `004ab6d`, which is the node ID portion. UIDs with a different suffix reference objects whose home node is elsewhere in the network — these can't be resolved from this disk alone.

## Files

| File | Description |
|------|-------------|
| `apollo_fs.py` | CLI and interactive shell |
| `apollo_core.py` | Library: constants, dataclasses, `ApolloFS` class |
| `aegis_internals.pdf` | *AEGIS Internals and Data Structures*, Apollo Computer Inc., Jan 1986 (426 pages) |
| `tree.txt` | Full recursive tree listing of the disk |

## References

- *AEGIS Internals and Data Structures*, Apollo Computer Inc., January 1986 (included as `aegis_internals.pdf`)
- [Apollo Computer](https://en.wikipedia.org/wiki/Apollo_Computer) — Wikipedia
- [Domain/OS](https://en.wikipedia.org/wiki/Domain/OS) — Wikipedia
- [Bitsavers Apollo documentation](http://bitsavers.org/pdf/apollo/) — scanned manuals and technical documents
