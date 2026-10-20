#!/usr/bin/env python3
"""Build recovered client functions and validate Linux/Wine implementations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import random
import re
import struct
import subprocess
import sys

import pefile
from Crypto.Cipher import AES

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "cw_graph"))
sys.path.insert(0, str(HERE.parent / "cw_packet_decode"))
from store import file_sha256
from decode import SHUFFLE, crypt_aes, shuffle_iv

MAIN_SHA = "4384087a6df1991cb59fea6d1ef086dbe746c7a5af0705bfc39769f4cc56e276"
RVAS = ["0xcc12a0", "0xcc1970", "0xcc1af0", "0xcc3f30", "0x7475e0"]
TARGETS = ["linux-x64-asan", "windows-x64-wine", "windows-x64-client-dll"]


def generated_source(state, binary):
    if file_sha256(binary) != MAIN_SHA:
        raise ValueError("client reference hash differs")
    functions = {}
    for line in (state / "modules" / MAIN_SHA / "functions.jsonl").open():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # A background exporter can be writing the last line.
        if row["rva"] in RVAS and row["status"] == "ok":
            functions[row["rva"]] = row["c"]
        if len(functions) == len(RVAS):
            break
    if set(functions) != set(RVAS):
        raise ValueError("required recovered function body is not available")
    pe = pefile.PE(str(binary), fast_load=True)
    image = pe.get_memory_mapped_image()
    bodies = "\n".join(functions[rva] for rva in RVAS)
    ranges = [(0x3b17940, 0x3b17a40), (0x3b53c50, 0x3b58080)]
    arrays, branches = [], []
    for i, (start, end) in enumerate(ranges):
        data = image[start:end].ljust(end - start, b"\0")
        arrays.append(f"_Alignas(16) static unsigned char cw_data_{i}[] = {{" + ",".join(map(str, data)) + "};")
        branches.append(f"if (rva >= {start} && rva < {end}) return cw_data_{i} + rva - {start};")
    definitions = []
    for address in sorted(set(re.findall(r"\bDAT_([a-fA-F0-9]+)\b", bodies))):
        rva = int(address, 16) - pe.OPTIONAL_HEADER.ImageBase
        if not any(a <= rva < b for a, b in ranges):
            raise ValueError(f"unhandled recovered global {address}")
        ctype = "uint" if rva == 0x3b53c58 or rva >= 0x3b54080 else "byte"
        if rva == 0x3b53d80:
            ctype = "char"
        definitions.append(f"#define DAT_{address} (*({ctype} *)cw_address({rva}))")
    preimages = [pe.get_data(int(rva, 16), 32).hex() for rva in RVAS]
    source = """/* Generated from pinned Ghidra bodies. Do not edit generated bodies. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t byte;
typedef uint32_t uint;
typedef uint32_t undefined4;
typedef int64_t longlong;
typedef uint64_t ulonglong;
#ifdef CW_TEST_MAIN
""" + "\n".join(arrays) + "\nstatic unsigned char *cw_address(size_t rva) {\n" + "\n".join(branches) + "\nabort();\n}\n#else\nstatic unsigned char *cw_image;\n#define cw_address(rva) (cw_image + (rva))\n#endif\n"
    source += "\n".join(definitions) + "\n" + bodies
    source += "\n#ifdef CW_TEST_MAIN\n" + (HERE / "driver.c").read_text() + "\n#else\n"
    source += "static const size_t cw_patch_rvas[] = {" + ",".join(RVAS) + "};\n"
    source += "static const unsigned char cw_patch_bytes[5][32] = {" + ",".join("{" + ",".join(str(b) for b in bytes.fromhex(v)) + "}" for v in preimages) + "};\n"
    source += (HERE / "runtime.c").read_text() + "\n#endif\n"
    pe.close()
    return source, functions, preimages


def arbitrary_shuffle(data, state):
    state = bytearray(struct.pack("<I", state))
    for value in data:
        state[0] = (state[0] + SHUFFLE[state[1]] - value) & 255
        state[1] = (state[1] - (state[2] ^ SHUFFLE[value])) & 255
        state[2] ^= (value + SHUFFLE[state[3]]) & 255
        state[3] = (state[3] - state[0] + SHUFFLE[value]) & 255
        word = int.from_bytes(state, "little")
        state[:] = ((word << 3 | word >> 29) & 0xffffffff).to_bytes(4, "little")
    return bytes(state)


def write_vectors(directory, capture_dir):
    rng = random.Random(0x52454255494c44)
    count = capture_count = 0
    inputs = directory / "vectors.bin"
    expected = directory / "expected.bin"
    with inputs.open("wb") as source, expected.open("wb") as output:
        def add(operation, data, iv, result):
            nonlocal count
            source.write(struct.pack("<BII", operation, len(data), iv) + data)
            output.write(result)
            count += 1
        for i in range(256):
            key, block = ((bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff"))
                          if i == 0 else (rng.randbytes(32), rng.randbytes(16)))
            add(0, key + block, 0, AES.new(key, AES.MODE_ECB).encrypt(block))
        for length in [0, 1, 2, 4, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1455, 1456, 1457,
                       1459, 1460, 1461, 2916, 10000, 65535, 65536, 65537, 131073]:
            data, iv = rng.randbytes(length), rng.getrandbits(32)
            add(1, data, iv, arbitrary_shuffle(data, iv))
            decoded = bytes((v - (iv & 255)) & 255 for v in data)
            add(2, data, iv, decoded)
            add(3, data, iv, decoded)
            add(4, data, iv, crypt_aes(data, struct.pack("<I", iv)))
        # Exercise the complete recording, maintaining each direction's IV.
        for stream, initial in [(61, {"client_to_server": "0b583a2e", "server_to_client": "7156bc60"}),
                                (91, {"client_to_server": "b079ec99", "server_to_client": "67984b14"})]:
            ivs = {k: bytes.fromhex(v) for k, v in initial.items()}
            for line in (capture_dir / f"stream-{stream}.jsonl").open():
                row = json.loads(line)
                data = bytes.fromhex(row["plaintext_hex"])
                if len(data) != row["length"] or hashlib.sha256(data).hexdigest() != row["plaintext_sha256"]:
                    raise ValueError("capture export hash mismatch")
                iv = ivs[row["direction"]]
                value = int.from_bytes(iv, "little")
                if stream == 91 and row["direction"] == "server_to_client":
                    encoded = bytes((v + iv[0]) & 255 for v in data)
                    add(3, encoded, value, data)
                else:
                    add(4, data, value, crypt_aes(data, iv))
                add(1, iv, 0xc65053f2, shuffle_iv(iv))
                ivs[row["direction"]] = shuffle_iv(iv)
                capture_count += 1
    return {"cases": count, "capture_packets": capture_count,
            "input_sha256": file_sha256(inputs), "output_sha256": file_sha256(expected)}


def save_report(directory, source, functions, results):
    report = {"scope": "five recovered client transport functions; hybrid runtime", "binary_sha256": MAIN_SHA,
              "source": str(source.resolve()), "source_sha256": file_sha256(source), "required_targets": TARGETS,
              "functions": [{"id": MAIN_SHA + ":" + rva, "body_sha256": hashlib.sha256(body.encode()).hexdigest()}
                            for rva, body in functions.items()], "results": results}
    temporary = directory / "validation.json.partial"
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(directory / "validation.json")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=REPO / "downloads/cw_graph")
    parser.add_argument("--binary", type=Path, default=REPO.parent / "maplestorycw/appdata/MapleStory.exe")
    parser.add_argument("--capture-dir", type=Path, default=REPO / "downloads/cw_decode/export")
    parser.add_argument("--wine-prefix", type=Path, default=REPO / "downloads/cw_wine/prefix")
    args = parser.parse_args()
    directory = args.state.resolve() / "validation/client-transport"
    directory.mkdir(parents=True, exist_ok=True)
    source_text, functions, preimages = generated_source(args.state, args.binary)
    source = directory / "client-transport.c"
    source.write_text(source_text)
    vectors = write_vectors(directory, args.capture_dir)
    results = []
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-parentheses", "-fno-strict-aliasing", "-fwrapv"]
    for target, compiler, extra in [(TARGETS[0], "gcc", ["-O1", "-fsanitize=address", "-fno-omit-frame-pointer"]),
                                    (TARGETS[1], "x86_64-w64-mingw32-gcc", ["-O2"]),
                                    (TARGETS[2], "x86_64-w64-mingw32-gcc", ["-O2"])]:
        is_dll = target == TARGETS[2]
        artifact = directory / ("cw_rebuilt.dll" if is_dll else "transport-test.exe" if target == TARGETS[1] else "transport-test")
        obj = directory / (target + ".o")
        record = {"target": target, "compile_status": "pending", "link_status": "pending", "run_status": "pending"}
        results.append(record)
        phase = "compile_status"
        try:
            compile_command = [compiler, *flags, *extra, *([] if is_dll else ["-DCW_TEST_MAIN"]), "-c", str(source), "-o", str(obj)]
            link_command = [compiler, *extra, *(["-shared", "-Wl,--exclude-all-symbols"] if is_dll else []), str(obj), "-o", str(artifact)]
            record.update(compile_command=compile_command, link_command=link_command)
            compiled = subprocess.run(compile_command, capture_output=True)
            (directory / (target + "-compile.log")).write_bytes(compiled.stdout + compiled.stderr)
            if compiled.returncode:
                raise RuntimeError(f"{target}: compile failed; see compile log")
            record["compile_status"] = "passed"
            phase = "link_status"
            linked = subprocess.run(link_command, capture_output=True)
            (directory / (target + "-link.log")).write_bytes(linked.stdout + linked.stderr)
            if linked.returncode:
                raise RuntimeError(f"{target}: link failed; see link log")
            record.update(link_status="passed", executable=str(artifact), executable_sha256=file_sha256(artifact))
            phase = "run_status"
            if not is_dll:
                command = [str(artifact)]
                if target == TARGETS[1]:
                    command = ["sudo", "-n", "ip", "netns", "exec", "maple-cw-local", "runuser", "-u", pwd.getpwuid(os.getuid()).pw_name,
                               "--", "env", "DISPLAY=:97", "WINEPREFIX=" + str(args.wine_prefix.resolve()), "WINEDEBUG=-all", "wine", *command]
                actual = directory / (target + "-actual.bin")
                with (directory / "vectors.bin").open("rb") as inputs, actual.open("wb") as output, (directory / (target + "-run.log")).open("wb") as error:
                    execution = subprocess.run(command, stdin=inputs, stdout=output, stderr=error, timeout=240)
                if execution.returncode or file_sha256(actual) != vectors["output_sha256"]:
                    raise RuntimeError(f"{target}: runtime mismatch, exit={execution.returncode}")
                record.update(run_status="passed", **vectors)
            # The DLL is only marked tested after actual gameplay evidence.
            save_report(directory, source, functions, results)
        except Exception as error:
            record[phase] = "failed"
            record["error"] = str(error)
            save_report(directory, source, functions, results)
            raise
    manifest = {"reference_sha256": MAIN_SHA, "dll": str((directory / "cw_rebuilt.dll").resolve()),
                "dll_sha256": file_sha256(directory / "cw_rebuilt.dll"),
                "validation": str(directory / "validation.json"),
                "functions": [{"rva": rva, "preimage": preimage} for rva, preimage in zip(RVAS, preimages)]}
    (directory / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"build": str(directory / "build.json"), "vectors": vectors, "results": results}, indent=2))


if __name__ == "__main__":
    main()
