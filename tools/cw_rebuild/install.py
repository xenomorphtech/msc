"""Add a pinned recovered-code DLL import to the disposable Wine client copy."""
import hashlib
import json
from pathlib import Path
import shutil
import struct

import pefile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def align(value, boundary):
    return (value + boundary - 1) // boundary * boundary


def add_import(data, dll="cw_rebuilt.dll", symbol="cw_rebuilt_probe"):
    pe = pefile.PE(data=data)
    if any(entry.dll.lower() == dll.lower().encode() for entry in pe.DIRECTORY_ENTRY_IMPORT):
        raise ValueError("rebuilt DLL import already exists")
    offset = pe.sections[-1].get_file_offset() + 40
    first_raw = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)
    if offset + 40 > first_raw or any(data[offset:offset + 40]):
        raise ValueError("no free PE section-header slot")
    rva = align(max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in pe.sections), pe.OPTIONAL_HEADER.SectionAlignment)
    raw = align(len(data), pe.OPTIONAL_HEADER.FileAlignment)
    descriptors = b"".join(entry.struct.__pack__() for entry in pe.DIRECTORY_ENTRY_IMPORT)
    payload = bytearray(len(descriptors) + 40)
    def append(value, boundary=1):
        payload.extend(b"\0" * (align(len(payload), boundary) - len(payload)))
        at = rva + len(payload)
        payload.extend(value)
        return at
    name_rva = append(dll.encode() + b"\0")
    symbol_rva = append(b"\0\0" + symbol.encode() + b"\0", 2)
    lookup = append(struct.pack("<QQ", symbol_rva, 0), 8)
    iat = append(struct.pack("<QQ", symbol_rva, 0), 8)
    payload[:len(descriptors)] = descriptors
    struct.pack_into("<IIIII", payload, len(descriptors), lookup, 0, 0, name_rva, iat)
    virtual_size = len(payload)
    raw_size = align(virtual_size, pe.OPTIONAL_HEADER.FileAlignment)
    payload.extend(b"\0" * (raw_size - virtual_size))
    result = bytearray(data)
    result.extend(b"\0" * (raw - len(result)))
    result.extend(payload)
    result[offset:offset + 40] = struct.pack("<8sIIIIIIHHI", b".cwbuild", virtual_size, rva, raw_size, raw, 0, 0, 0, 0, 0xc0000040)
    struct.pack_into("<H", result, pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"), pe.FILE_HEADER.NumberOfSections + 1)
    struct.pack_into("<I", result, pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"), align(rva + virtual_size, pe.OPTIONAL_HEADER.SectionAlignment))
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    struct.pack_into("<II", result, directory.get_file_offset(), rva, len(descriptors) + 40)
    bound = pe.OPTIONAL_HEADER.DATA_DIRECTORY[11]
    struct.pack_into("<II", result, bound.get_file_offset(), 0, 0)
    struct.pack_into("<I", result, pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum"), 0)
    struct.pack_into("<I", result, pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfInitializedData"), pe.OPTIONAL_HEADER.SizeOfInitializedData + raw_size)
    pe.close()
    check = pefile.PE(data=bytes(result))
    assert check.DIRECTORY_ENTRY_IMPORT[-1].dll == dll.encode()
    assert check.DIRECTORY_ENTRY_IMPORT[-1].imports[0].name == symbol.encode()
    check.close()
    return bytes(result)


def install(client, original_sha, manifest_path, dll_name="cw_rebuilt.dll", symbol="cw_rebuilt_probe", runtime_target="windows-x64-client-dll"):
    manifest = json.loads(manifest_path.read_text())
    if manifest["reference_sha256"] != original_sha:
        raise ValueError("rebuild reference hash differs from the launcher's original client")
    dll = Path(manifest["dll"])
    if sha(dll.read_bytes()) != manifest["dll_sha256"]:
        raise ValueError("rebuilt DLL hash differs from its build manifest")
    validation = json.loads(Path(manifest["validation"]).read_text())
    if sha(Path(validation["source"]).read_bytes()) != validation["source_sha256"]:
        raise ValueError("validated source changed")
    if len(validation["results"]) != 3 or any(r["compile_status"] != "passed" or r["link_status"] != "passed"
                                            for r in validation["results"]):
        raise ValueError("all three build targets must compile and link before launch")
    for result in validation["results"]:
        if sha(Path(result["executable"]).read_bytes()) != result["executable_sha256"]:
            raise ValueError("validated build artifact changed")
        if result["target"] != runtime_target and result["run_status"] != "passed":
            raise ValueError("both standalone runtime tests must pass before launch")
    target = next(r for r in validation["results"] if r["target"] == runtime_target)
    if target["executable_sha256"] != manifest["dll_sha256"]:
        raise ValueError("DLL differs from its validated target")
    executable = client / "MapleStory.exe"
    before = executable.read_bytes()
    pe = pefile.PE(data=before)
    for entry in manifest["functions"]:
        expected = bytes.fromhex(entry["preimage"])
        if pe.get_data(int(entry["rva"], 16), len(expected)) != expected:
            raise ValueError(f"unexpected function preimage: {entry['rva']}")
    pe.close()
    rebuilt = add_import(before, dll_name, symbol)
    shutil.copyfile(dll, client / dll_name)
    executable.write_bytes(rebuilt)
    evidence = {**manifest, "input_sha256": sha(before), "hybrid_client_sha256": sha(rebuilt)}
    (client / (Path(dll_name).stem.replace("_", "-") + "-build.json")).write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence
