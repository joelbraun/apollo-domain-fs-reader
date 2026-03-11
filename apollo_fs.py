#!/usr/bin/env python3
"""
Apollo Domain/OS Filesystem Reader

Reverse-engineered from a disk image taken off an HP 9000 Series 400
Apollo workstation. Based on the AEGIS Internals and Data Structures
document (Jan 1986) with adjustments for the later 4K-block format.

Disk layout (4K blocks, 512-byte sector dd image):
  Physical DADDR 0: PV label (overwritten by Solaris VTOC on this image)
  Physical DADDR 1: LV label (logical DADDR 0)
  Physical DADDR 2-11: SYSBOOT (logical DADDR 1-10)
  ...user data...
  BAT (bitmap): ~middle of disk
  VTOC (hash table of VTOCEs): after BAT
  ...more data...
"""

import datetime
import mmap
import os
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional

BLOCK_SIZE = 4096
VTOCX_INDEX_BITS = 4
VTOCX_INDEX_MASK = (1 << VTOCX_INDEX_BITS) - 1

VTOCE_SIZE = 0x1D0  # 464 bytes, 8 per 4K VTOC block
VTOCES_PER_BLOCK = 8
VTOC_BLOCK_HEADER_SIZE = 4

DIR_ENTRY_TYPE_OBJECT = 0x02
DIR_ENTRY_TYPE_OBJECT_ALT = 0x82
DIR_ENTRY_TYPE_LINK = 0x04
DIR_HASH_TABLE_OFFSET = 0x80


@dataclass(frozen=True)
class UID:
    high: int
    low: int

    def __str__(self):
        return f"{self.high:08x}.{self.low:08x}"

    def __hash__(self):
        return hash((self.high, self.low))

    @property
    def is_zero(self):
        return self.high == 0 and self.low == 0


@dataclass
class BATHeader:
    total_blocks: int
    free_blocks: int
    first_bat_daddr: int
    first_bat_block_num: int

    @property
    def used_blocks(self):
        return self.total_blocks - self.free_blocks


@dataclass(frozen=True)
class VTOCIndex:
    raw: int

    @property
    def daddr(self):
        return self.raw >> VTOCX_INDEX_BITS

    @property
    def index(self):
        return self.raw & VTOCX_INDEX_MASK

    def __str__(self):
        return f"VTOCX(daddr=0x{self.daddr:x}, idx={self.index})"


@dataclass
class VTOCE:
    raw: bytes
    block_offset: int
    vtocx: Optional[VTOCIndex] = None

    @property
    def in_use(self):
        return len(self.raw) >= 16 and self.raw[4] != 0x55 and self.raw[6] == 0x90

    @property
    def object_uid(self):
        high, low = struct.unpack('>II', self.raw[8:16])
        return UID(high, low)

    @property
    def current_length(self):
        """Object size in bytes - at VTOCE offset 0x18"""
        if len(self.raw) >= 0x1C:
            return struct.unpack('>I', self.raw[0x18:0x1C])[0]
        return 0

    @property
    def blocks_used(self):
        """Number of blocks used - at VTOCE offset 0x1C"""
        if len(self.raw) >= 0x20:
            return struct.unpack('>I', self.raw[0x1C:0x20])[0]
        return 0

    @property
    def page_addresses(self):
        addrs = []
        page_offset = 0xD4
        for i in range(32):
            off = page_offset + i * 4
            if off + 4 <= len(self.raw):
                addr = struct.unpack('>I', self.raw[off:off+4])[0]
                addrs.append(addr)
        return addrs

    @property
    def file_map_ptrs(self):
        fm_offset = 0xD4 + 32 * 4
        ptrs = []
        for i in range(3):
            off = fm_offset + i * 4
            if off + 4 <= len(self.raw):
                ptr = struct.unpack('>I', self.raw[off:off+4])[0]
                ptrs.append(ptr)
        return ptrs


@dataclass
class DirEntry:
    entry_type: int
    name: str
    uid: Optional[UID]
    link_target: Optional[str]

    @property
    def is_link(self):
        return self.entry_type == DIR_ENTRY_TYPE_LINK

    @property
    def type_str(self):
        if self.entry_type == DIR_ENTRY_TYPE_LINK:
            return "LINK"
        elif self.entry_type in (DIR_ENTRY_TYPE_OBJECT, DIR_ENTRY_TYPE_OBJECT_ALT):
            return "OBJ "
        return f"0x{self.entry_type:02x}"

    def __str__(self):
        if self.is_link:
            return f"{self.type_str} {self.name} -> {self.link_target}"
        return f"{self.type_str} {self.name}  [{self.uid}]"


# ── Directory entry parsing ──

def parse_dir_entry_at(block: bytes, pos: int) -> Optional[DirEntry]:
    if pos + 12 > len(block):
        return None

    entry_type = block[pos]
    name_len = block[pos + 1]

    if name_len == 0 or name_len > 200:
        return None

    if entry_type in (DIR_ENTRY_TYPE_OBJECT, DIR_ENTRY_TYPE_OBJECT_ALT):
        if pos + 16 + name_len > len(block):
            return None
        uid_high = struct.unpack('>I', block[pos+4:pos+8])[0]
        uid_low = struct.unpack('>I', block[pos+8:pos+12])[0]
        name = block[pos+16:pos+16+name_len].decode('ascii', errors='replace')
        return DirEntry(entry_type=entry_type, name=name,
                        uid=UID(uid_high, uid_low), link_target=None)

    elif entry_type == DIR_ENTRY_TYPE_LINK:
        target_len = struct.unpack('>H', block[pos+2:pos+4])[0]
        name_start = pos + 12
        if name_start + name_len > len(block):
            return None
        name = block[name_start:name_start+name_len].decode('ascii', errors='replace')
        target_start = name_start + name_len
        target_end = min(target_start + target_len, len(block))
        target = block[target_start:target_end].rstrip(b'\x00').decode('ascii', errors='replace')
        return DirEntry(entry_type=entry_type, name=name,
                        uid=None, link_target=target)

    return None


def entry_size_of(block: bytes, pos: int) -> int:
    entry_type = block[pos]
    name_len = block[pos + 1]

    if entry_type in (DIR_ENTRY_TYPE_OBJECT, DIR_ENTRY_TYPE_OBJECT_ALT):
        return 16 + ((name_len + 1 + 3) & ~3)
    elif entry_type == DIR_ENTRY_TYPE_LINK:
        target_len = struct.unpack('>H', block[pos+2:pos+4])[0]
        return 12 + ((name_len + target_len + 3) & ~3)
    return 16


def parse_dir_block(block: bytes) -> list:
    visited = set()
    entries = []

    pos = DIR_HASH_TABLE_OFFSET
    while pos + 2 <= len(block):
        offset_val = struct.unpack('>H', block[pos:pos+2])[0]
        pos += 2

        if offset_val == 0x0000 or offset_val == 0xFFFF:
            continue
        if offset_val < 0x100 or offset_val >= len(block):
            if pos > DIR_HASH_TABLE_OFFSET + 512:
                break
            continue
        if offset_val in visited:
            continue
        visited.add(offset_val)

        entry = parse_dir_entry_at(block, offset_val)
        if entry:
            entries.append(entry)
            chain_pos = offset_val + entry_size_of(block, offset_val)
            while chain_pos < len(block) - 12:
                next_entry = parse_dir_entry_at(block, chain_pos)
                if not next_entry:
                    break
                if chain_pos not in visited:
                    visited.add(chain_pos)
                    entries.append(next_entry)
                chain_pos += entry_size_of(block, chain_pos)

    return entries


# ── Main filesystem class ──

class ApolloFS:
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.image_size = os.path.getsize(image_path)
        self.f = open(image_path, 'rb')
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        self.total_4k_blocks = self.image_size // BLOCK_SIZE

        self._bat = None
        self._vtocxs = None
        self._vtoc_index: dict[UID, VTOCIndex] = {}
        self._vtoc_index_built = False

    def close(self):
        self.mm.close()
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def read_block(self, physical_daddr: int) -> bytes:
        offset = physical_daddr * BLOCK_SIZE
        return bytes(self.mm[offset:offset + BLOCK_SIZE])

    def read_logical_block(self, logical_daddr: int) -> bytes:
        return self.read_block(logical_daddr + 1)

    # ── LV Label ──

    def parse_lv_label(self):
        block = self.read_block(1)

        bat = BATHeader(
            total_blocks=struct.unpack('>I', block[0x2C:0x30])[0],
            free_blocks=struct.unpack('>I', block[0x30:0x34])[0],
            first_bat_daddr=struct.unpack('>I', block[0x34:0x38])[0],
            first_bat_block_num=struct.unpack('>I', block[0x38:0x3C])[0],
        )

        vtocx_offsets = [0x54, 0x58, 0x5C, 0x60]
        vtocx_names = ['Network Root Dir', 'Disk Entry Dir', 'OS Paging File', 'SYSBOOT']
        vtocxs = {}
        for off, name in zip(vtocx_offsets, vtocx_names):
            raw = struct.unpack('>I', block[off:off+4])[0]
            vtocxs[name] = VTOCIndex(raw)

        self._bat = bat
        self._vtocxs = vtocxs
        return bat, vtocxs

    def get_bat(self):
        if self._bat is None:
            self.parse_lv_label()
        return self._bat

    def get_vtocxs(self):
        if self._vtocxs is None:
            self.parse_lv_label()
        return self._vtocxs

    # ── VTOC reading ──

    def read_vtoc_block(self, logical_daddr: int):
        block = self.read_logical_block(logical_daddr)
        next_ptr = struct.unpack('>I', block[0:4])[0]
        entries = []
        for i in range(VTOCES_PER_BLOCK):
            start = VTOC_BLOCK_HEADER_SIZE + i * VTOCE_SIZE
            end = start + VTOCE_SIZE
            if end > BLOCK_SIZE:
                break
            vtocx = VTOCIndex((logical_daddr << VTOCX_INDEX_BITS) | i)
            raw = block[start:end]
            entries.append(VTOCE(raw=raw, block_offset=start, vtocx=vtocx))
        return next_ptr, entries

    def read_vtoce(self, vtocx: VTOCIndex) -> Optional[VTOCE]:
        _, entries = self.read_vtoc_block(vtocx.daddr)
        idx = vtocx.index
        if idx < len(entries):
            return entries[idx]
        return None

    # ── VTOC Index (UID → VTOCX) ──

    def _find_vtoc_extent(self):
        """Auto-detect the VTOC extent by scanning outward from known VTOC blocks."""
        vtocxs = self.get_vtocxs()
        known_daddr = vtocxs['SYSBOOT'].daddr

        start = known_daddr
        while start > 0:
            phys = (start - 1 + 1) * BLOCK_SIZE
            if all(self.mm[phys+4+i] == 0x55 for i in range(8)):
                break
            start -= 1

        # Scan forward with a high tolerance for gaps (the VTOC hash table
        # is very sparse, with gaps of 30,000+ empty blocks between entries)
        # this is mostly a guess, but it seems to work well enough
        max_daddr = min(start + 200000, self.image_size // BLOCK_SIZE - 2)
        return start, max_daddr - start

    def build_vtoc_index(self):
        """Scan the VTOC extent to build a UID→VTOCX mapping."""
        if self._vtoc_index_built:
            return

        vtoc_start, vtoc_count = self._find_vtoc_extent()
        t0 = time.time()
        found = 0

        for i in range(vtoc_count):
            daddr = vtoc_start + i
            phys = (daddr + 1) * BLOCK_SIZE

            # Quick check: is the first VTOCE's in-use marker not 0x55?
            if self.mm[phys + 4 + 4] == 0x55:
                # Also check a couple more VTOCEs in the block
                has_any = False
                for j in range(1, VTOCES_PER_BLOCK):
                    off = phys + VTOC_BLOCK_HEADER_SIZE + j * VTOCE_SIZE + 4
                    if off < self.image_size and self.mm[off] != 0x55:
                        has_any = True
                        break
                if not has_any:
                    continue

            _, entries = self.read_vtoc_block(daddr)
            for vtoce in entries:
                if vtoce.in_use:
                    uid = vtoce.object_uid
                    if not uid.is_zero:
                        self._vtoc_index[uid] = vtoce.vtocx
                        found += 1

        elapsed = time.time() - t0
        print(f"VTOC index: {found} objects in {elapsed:.2f}s "
              f"(extent: 0x{vtoc_start:x}, {vtoc_count} blocks)",
              file=sys.stderr)
        self._vtoc_index_built = True

    def lookup_uid(self, uid: UID) -> Optional[VTOCIndex]:
        """Look up a UID in the VTOC index, building it if needed."""
        if not self._vtoc_index_built:
            self.build_vtoc_index()
        return self._vtoc_index.get(uid)

    # ── Object data reading ──

    def read_object_data(self, vtoce: VTOCE) -> bytes:
        """Read all data pages for an object, following file maps if needed."""
        pages = vtoce.page_addresses
        data_blocks = []

        for daddr in pages:
            if daddr == 0:
                data_blocks.append(b'\x00' * BLOCK_SIZE)
            else:
                data_blocks.append(self.read_logical_block(daddr))

        # If there are file map pointers, follow them for larger objects
        for level, fm_daddr in enumerate(vtoce.file_map_ptrs):
            if fm_daddr == 0:
                continue
            fm_block = self.read_logical_block(fm_daddr)
            # Level 1 file map: array of 1024 DADDRs (4 bytes each)
            for i in range(0, BLOCK_SIZE, 4):
                daddr = struct.unpack('>I', fm_block[i:i+4])[0]
                if daddr == 0:
                    data_blocks.append(b'\x00' * BLOCK_SIZE)
                else:
                    data_blocks.append(self.read_logical_block(daddr))
            # Only handle L1 for now; L2/L3 for very large files can be added later
            # no idea what the max size of a file is anyway
            break

        return b''.join(data_blocks)

    # ── Directory operations ──

    def list_directory_by_vtocx(self, vtocx: VTOCIndex) -> list:
        vtoce = self.read_vtoce(vtocx)
        if not vtoce or not vtoce.in_use:
            return []

        all_entries = []
        for daddr in vtoce.page_addresses:
            if daddr == 0:
                continue
            block = self.read_logical_block(daddr)
            all_entries.extend(parse_dir_block(block))

        return [e for e in all_entries
                if e.name and e.name.strip('\x00')]

    def list_directory_by_uid(self, uid: UID) -> list:
        vtocx = self.lookup_uid(uid)
        if vtocx is None:
            return []
        return self.list_directory_by_vtocx(vtocx)

    def resolve_path(self, path: str) -> Optional[UID]:
        """Resolve a filesystem path to a UID.
        Paths starting with // use the Network Root Dir.
        All other paths use the Disk Entry Dir.
        """
        vtocxs = self.get_vtocxs()

        if path.startswith('//'):
            root_vtocx = vtocxs['Network Root Dir']
            parts = [p for p in path[2:].split('/') if p]
        else:
            root_vtocx = vtocxs['Disk Entry Dir']
            parts = [p for p in path.strip('/').split('/') if p]

        if not parts:
            vtoce = self.read_vtoce(root_vtocx)
            return vtoce.object_uid if vtoce else None

        current_vtocx = root_vtocx
        for i, part in enumerate(parts):
            entries = self.list_directory_by_vtocx(current_vtocx)
            found = None
            for e in entries:
                if e.name == part and not e.is_link:
                    found = e
                    break
            if found is None:
                remaining = '/'.join(parts[i:])
                print(f"Not found: '{remaining}' in directory")
                return None

            vtocx = self.lookup_uid(found.uid)
            if vtocx is None:
                print(f"UID {found.uid} not found in VTOC")
                return None
            current_vtocx = vtocx

        vtoce = self.read_vtoce(current_vtocx)
        return vtoce.object_uid if vtoce else None

    # ── CLI commands ──

    def cmd_analyze(self):
        print("=" * 60)
        print("Apollo Domain/OS Filesystem Analyzer")
        print("=" * 60)
        print(f"\nImage: {self.image_path}")
        print(f"Size: {self.image_size:,} bytes ({self.image_size/1024/1024/1024:.3f} GB)")
        print(f"Blocks (4096B): {self.total_4k_blocks:,}")

        sector0 = bytes(self.mm[0:512])

        bat = self.get_bat()
        vtocxs = self.get_vtocxs()

        print(f"\nLV Label (physical DADDR 1):")
        block = self.read_block(1)
        lv_name = block[0x04:0x24].rstrip(b'\x00').rstrip(b' ')
        lv_uid = UID(*struct.unpack('>II', block[0x24:0x2C]))
        print(f"  Name: '{lv_name.decode('ascii', errors='replace')}'")
        print(f"  UID:  {lv_uid}")

        print(f"\nBAT: {bat.total_blocks} total, {bat.free_blocks} free, "
              f"{bat.used_blocks} used ({bat.used_blocks*100//bat.total_blocks}%)")

        print(f"\nSpecial objects:")
        for name, vtocx in vtocxs.items():
            vtoce = self.read_vtoce(vtocx)
            uid_str = str(vtoce.object_uid) if vtoce and vtoce.in_use else "?"
            print(f"  {name:<20} {vtocx}  UID={uid_str}")

        self.build_vtoc_index()

    def cmd_ls(self, path: str = "/"):
        vtocxs = self.get_vtocxs()

        if path == "/" or path == "":
            vtocx = vtocxs['Disk Entry Dir']
            label = "/"
        elif path == "//":
            vtocx = vtocxs['Network Root Dir']
            label = "//"
        else:
            self.build_vtoc_index()
            uid = self.resolve_path(path)
            if uid is None:
                print(f"Cannot resolve path: {path}")
                return
            vtocx = self.lookup_uid(uid)
            if vtocx is None:
                print(f"UID {uid} not in VTOC")
                return
            label = path

        entries = self.list_directory_by_vtocx(vtocx)

        print(f"\nDirectory: {label}")
        print(f"{'Type':<6} {'Name':<32} {'UID / Target'}")
        print("-" * 72)
        for entry in sorted(entries, key=lambda e: e.name.lower()):
            if not entry.name:
                continue
            if entry.is_link:
                print(f"{entry.type_str:<6} {entry.name:<32} -> {entry.link_target}")
            else:
                print(f"{entry.type_str:<6} {entry.name:<32} [{entry.uid}]")
        print(f"\n{len(entries)} entries")

    def cmd_tree(self, path: str = "/", max_depth: int = 2):
        """Recursively list directories."""
        vtocxs = self.get_vtocxs()
        self.build_vtoc_index()

        if path == "/" or path == "":
            root_vtocx = vtocxs['Disk Entry Dir']
        elif path == "//":
            root_vtocx = vtocxs['Network Root Dir']
        else:
            uid = self.resolve_path(path)
            if uid is None:
                return
            root_vtocx = self.lookup_uid(uid)
            if root_vtocx is None:
                return

        print(f"\n{path}")
        self._print_tree(root_vtocx, "", max_depth, 0)

    def _print_tree(self, vtocx: VTOCIndex, prefix: str, max_depth: int, depth: int):
        entries = self.list_directory_by_vtocx(vtocx)
        entries = [e for e in entries if e.name]
        entries.sort(key=lambda e: e.name.lower())

        for i, entry in enumerate(entries):
            is_last = (i == len(entries) - 1)
            connector = "└── " if is_last else "├── "

            if entry.is_link:
                print(f"{prefix}{connector}{entry.name} -> {entry.link_target}")
            else:
                print(f"{prefix}{connector}{entry.name}")

                if depth < max_depth and entry.uid:
                    child_vtocx = self.lookup_uid(entry.uid)
                    if child_vtocx:
                        child_vtoce = self.read_vtoce(child_vtocx)
                        if child_vtoce and child_vtoce.in_use:
                            # Check if this looks like a directory (has page data)
                            has_pages = any(d != 0 for d in child_vtoce.page_addresses)
                            if has_pages:
                                child_entries = self.list_directory_by_vtocx(child_vtocx)
                                if child_entries and any(e.name for e in child_entries):
                                    ext = "    " if is_last else "│   "
                                    self._print_tree(child_vtocx, prefix + ext,
                                                     max_depth, depth + 1)

    def cmd_cat(self, path: str):
        """Print file contents."""
        self.build_vtoc_index()
        uid = self.resolve_path(path)
        if uid is None:
            return
        vtocx = self.lookup_uid(uid)
        if vtocx is None:
            print(f"UID {uid} not in VTOC")
            return
        vtoce = self.read_vtoce(vtocx)
        if not vtoce:
            return

        data = self.read_object_data(vtoce)
        size = vtoce.current_length
        if size > 0:
            data = data[:size]
        else:
            data = data.rstrip(b'\x00')
        try:
            text = data.decode('ascii', errors='replace')
            print(text)
        except Exception:
            sys.stdout.buffer.write(data)

    def cmd_stat(self, path: str):
        """Show detailed object metadata."""
        self.build_vtoc_index()
        uid = self.resolve_path(path)
        if uid is None:
            return
        vtocx = self.lookup_uid(uid)
        if vtocx is None:
            print(f"UID {uid} not in VTOC")
            return
        vtoce = self.read_vtoce(vtocx)
        if not vtoce:
            return

        print(f"  Path: {path}")
        print(f"  UID:  {vtoce.object_uid}")
        print(f"  Size: {vtoce.current_length} bytes")
        print(f"  Blocks: {vtoce.blocks_used}")
        print(f"  VTOCX: daddr=0x{vtocx.daddr:x} idx={vtocx.index}")

        apollo_epoch = datetime.datetime(1980, 1, 1, tzinfo=datetime.timezone.utc)
        if len(vtoce.raw) >= 0x24:
            ts = struct.unpack('>I', vtoce.raw[0x20:0x24])[0]
            if ts > 0:
                try:
                    dt = apollo_epoch + datetime.timedelta(seconds=ts)
                    print(f"  Modified: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                except (OverflowError, OSError):
                    print(f"  Modified: 0x{ts:08x} (raw)")

        if len(vtoce.raw) >= 0x48:
            parent_hi = struct.unpack('>I', vtoce.raw[0x40:0x44])[0]
            parent_lo = struct.unpack('>I', vtoce.raw[0x44:0x48])[0]
            if parent_hi != 0:
                parent = UID(parent_hi, parent_lo)
                print(f"  Parent: {parent}")

        pages = vtoce.page_addresses
        nonzero = [(i, d) for i, d in enumerate(pages) if d != 0]
        if nonzero:
            print(f"  Pages ({len(nonzero)} mapped):")
            for i, d in nonzero:
                print(f"    [{i:2d}] -> daddr 0x{d:x}")

    def cmd_find(self, pattern: str, path: str = "/"):
        """Search for files/dirs matching a pattern (case-insensitive substring)."""
        import fnmatch
        self.build_vtoc_index()
        vtocxs = self.get_vtocxs()

        if path == "/" or path == "":
            root_vtocx = vtocxs['Disk Entry Dir']
        else:
            uid = self.resolve_path(path)
            if uid is None:
                return
            root_vtocx = self.lookup_uid(uid)
            if root_vtocx is None:
                return

        pat_lower = pattern.lower()
        use_glob = any(c in pattern for c in '*?[]')
        hits = 0

        def walk(vtocx, current_path):
            nonlocal hits
            entries = self.list_directory_by_vtocx(vtocx)
            for e in entries:
                if not e.name:
                    continue
                full = f"{current_path}/{e.name}" if current_path != "/" else f"/{e.name}"

                matched = (fnmatch.fnmatch(e.name.lower(), pat_lower) if use_glob
                           else pat_lower in e.name.lower())
                if matched:
                    if e.is_link:
                        print(f"{full} -> {e.link_target}")
                    else:
                        print(full)
                    hits += 1

                if not e.is_link and e.uid:
                    child_vtocx = self.lookup_uid(e.uid)
                    if child_vtocx:
                        child_vtoce = self.read_vtoce(child_vtocx)
                        if (child_vtoce and child_vtoce.in_use
                                and any(d != 0 for d in child_vtoce.page_addresses)):
                            child_entries = self.list_directory_by_vtocx(child_vtocx)
                            if child_entries and any(e.name for e in child_entries):
                                walk(child_vtocx, full)

        walk(root_vtocx, path.rstrip('/') or "/")
        print(f"\n{hits} matches", file=sys.stderr)

    def cmd_extract(self, path: str, output: str):
        """Extract a file to disk."""
        self.build_vtoc_index()
        uid = self.resolve_path(path)
        if uid is None:
            return
        vtocx = self.lookup_uid(uid)
        if vtocx is None:
            print(f"UID {uid} not in VTOC")
            return
        vtoce = self.read_vtoce(vtocx)
        if not vtoce:
            return

        data = self.read_object_data(vtoce)
        size = vtoce.current_length
        if size > 0:
            data = data[:size]
        with open(output, 'wb') as out:
            out.write(data)
        print(f"Extracted {size if size > 0 else len(data)} bytes to {output}")


def _normalize_path(cwd: str, path: str) -> str:
    """Resolve path relative to cwd. Handles / and // roots."""
    path = path.strip()
    if not path:
        return cwd
    if path.startswith('//'):
        return path.rstrip('/') or '//'
    if path.startswith('/'):
        return os.path.normpath(path) or '/'
    base = cwd.rstrip('/') or '/'
    joined = os.path.normpath(os.path.join(base, path))
    if not joined.startswith('/'):
        joined = '/' + joined
    return joined or '/'


HELP_TEXT = """
Apollo filesystem shell commands
───────────────────────────────

  help              Show this message
  pwd               Print current directory
  cd <path>         Change directory (use / for root, // for network root)
  ls [path]         List directory (default: current)
  tree [path] [N]   Recursive tree (default depth 2)
  find <pat> [path] Search by name; supports glob (* ? [])
  stat <path>       Show file/object metadata
  cat <path>        Print file contents
  extract <p> <out> Save file to disk
  analyze           Show filesystem metadata
  quit, exit        Exit the shell

Paths are relative to the current directory unless they start with /.
Examples:
  cd etc             go to etc/ in current dir
  cd /etc            go to /etc
  cd ..              go to parent directory
  ls                 list current directory
  find *.c /usr      find *.c under /usr
"""


def run_shell(fs: ApolloFS):
    """Interactive shell for exploring the Apollo image."""
    cwd = '/'
    print(f"Apollo filesystem shell — image: {fs.image_path}")
    print("Type 'help' for commands, 'quit' to exit.\n")

    while True:
        try:
            line = input(f"apollofs:{cwd}> ").strip()
        except EOFError:
            print()
            break
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ('quit', 'exit', 'q'):
            break
        if cmd == 'help':
            print(HELP_TEXT)
            continue
        if cmd == 'pwd':
            print(cwd)
            continue
        if cmd == 'cd':
            if not args:
                print("cd: usage: cd <path>")
                continue
            path = _normalize_path(cwd, args[0])
            fs.build_vtoc_index()
            uid = fs.resolve_path(path)
            if uid is None:
                continue
            vtocx = fs.lookup_uid(uid)
            if vtocx is None:
                print(f"cd: {path}: not found")
                continue
            vtoce = fs.read_vtoce(vtocx)
            if not vtoce or not vtoce.in_use:
                print(f"cd: {path}: not a directory")
                continue
            has_pages = any(d != 0 for d in vtoce.page_addresses)
            entries = fs.list_directory_by_vtocx(vtocx) if has_pages else []
            if not has_pages or not any(e.name for e in entries):
                print(f"cd: {path}: not a directory")
                continue
            cwd = path.rstrip('/') or ('//' if path.startswith('//') else '/')
            continue
        if cmd == 'ls':
            path = _normalize_path(cwd, args[0]) if args else cwd
            fs.cmd_ls(path)
            continue
        if cmd == 'tree':
            path = _normalize_path(cwd, args[0]) if args else cwd
            depth = int(args[1]) if len(args) > 1 else 2
            fs.cmd_tree(path, depth)
            continue
        if cmd == 'find':
            if not args:
                print("find: usage: find <pattern> [path]")
                continue
            path = _normalize_path(cwd, args[1]) if len(args) > 1 else cwd
            fs.cmd_find(args[0], path)
            continue
        if cmd == 'stat':
            if not args:
                print("stat: usage: stat <path>")
                continue
            path = _normalize_path(cwd, args[0])
            fs.cmd_stat(path)
            continue
        if cmd == 'cat':
            if not args:
                print("cat: usage: cat <path>")
                continue
            path = _normalize_path(cwd, args[0])
            fs.cmd_cat(path)
            continue
        if cmd == 'extract':
            if len(args) < 2:
                print("extract: usage: extract <path> <output>")
                continue
            path = _normalize_path(cwd, args[0])
            fs.cmd_extract(path, args[1])
            continue
        if cmd == 'analyze':
            fs.cmd_analyze()
            continue

        print(f"Unknown command: {cmd}. Type 'help' for available commands.")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <image> [command] [args]")
        print(f"  With no command: start interactive shell")
        print(f"  Commands: analyze, ls, tree, find, stat, cat, extract")
        print(f"  Type 'help' in the shell for interactive commands")
        sys.exit(1)

    image_path = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else None

    with ApolloFS(image_path) as fs:
        if cmd is None:
            run_shell(fs)
            return
        if cmd == 'analyze':
            fs.cmd_analyze()
        elif cmd == 'ls':
            path = sys.argv[3] if len(sys.argv) > 3 else '/'
            fs.cmd_ls(path)
        elif cmd == 'tree':
            path = sys.argv[3] if len(sys.argv) > 3 else '/'
            depth = int(sys.argv[4]) if len(sys.argv) > 4 else 2
            fs.cmd_tree(path, depth)
        elif cmd == 'find':
            if len(sys.argv) < 4:
                print("Usage: find <pattern> [path]")
                sys.exit(1)
            path = sys.argv[4] if len(sys.argv) > 4 else '/'
            fs.cmd_find(sys.argv[3], path)
        elif cmd == 'stat':
            if len(sys.argv) < 4:
                print("Usage: stat <path>")
                sys.exit(1)
            fs.cmd_stat(sys.argv[3])
        elif cmd == 'cat':
            if len(sys.argv) < 4:
                print("Usage: cat <path>")
                sys.exit(1)
            fs.cmd_cat(sys.argv[3])
        elif cmd == 'extract':
            if len(sys.argv) < 5:
                print("Usage: extract <path> <output>")
                sys.exit(1)
            fs.cmd_extract(sys.argv[3], sys.argv[4])
        else:
            print(f"Unknown command: {cmd}")


if __name__ == '__main__':
    main()
