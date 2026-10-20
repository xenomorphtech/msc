"""Independent x64 unwind-table inventory, including chained function fragments."""
from collections import defaultdict
import json
from pathlib import Path
import struct

import pefile


def expected_functions(binary):
    if "expected_functions" in binary:  # Small explicit fixtures need no copyrighted PE.
        yield from binary["expected_functions"]
        return
    pe = pefile.PE(binary["path"], fast_load=True)
    try:
        section = next((s for s in pe.sections if s.Name.rstrip(b"\0") == b".pdata"), None)
        if pe.FILE_HEADER.Machine != 0x8664 or section is None:
            return
        data = section.get_data()[:section.Misc_VirtualSize]
        entries = {}
        executable = [(s.VirtualAddress, s.VirtualAddress + min(s.Misc_VirtualSize, s.SizeOfRawData))
                      for s in pe.sections if s.Characteristics & 0x20000000 and s.SizeOfRawData]
        for begin, end, unwind in struct.iter_unpack("<III", data[:len(data) // 12 * 12]):
            if begin < end and end - begin <= 0x1000000 and any(a <= begin < end <= b for a, b in executable):
                entries[begin] = (begin, end, unwind)
        grouped = defaultdict(list)
        for entry, record in entries.items():
            root = entry
            seen = set()
            while root not in seen:
                seen.add(root)
                unwind = entries[root][2]
                header = pe.get_data(unwind, 4)
                if len(header) != 4 or not header[0] >> 3 & 4:
                    break
                chain = pe.get_data(unwind + 4 + ((header[2] + 1) & ~1) * 2, 12)
                if len(chain) != 12:
                    break
                parent = struct.unpack_from("<I", chain)[0]
                if parent not in entries:
                    break
                root = parent
            grouped[root].append([record[0], record[1] - 1])
        for root, ranges in sorted(grouped.items()):
            yield {"id": binary["id"] + ":" + hex(root), "binary_id": binary["id"], "rva": hex(root), "ranges": sorted(ranges)}
    finally:
        pe.close()


def baseline_records(state, binary):
    directory = state / "baseline"
    directory.mkdir(exist_ok=True)
    path = directory / (binary["id"] + ".jsonl")
    if not path.exists():
        staging = path.with_suffix(".partial")
        with staging.open("w") as stream:
            for row in expected_functions(binary):
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        staging.replace(path)
    with path.open() as stream:
        for line in stream:
            yield json.loads(line)
