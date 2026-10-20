#!/usr/bin/env python3
"""Compile unchanged recovered AES functions and test their execution against AES vectors.

This validates three recovered functions, not a reconstructed game client.
"""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import random
import re
import subprocess

from Crypto.Cipher import AES
import pefile
from store import file_sha256


ZLZ_SHA256 = "2db9ec805a0cfab78dabd8978f42af2129cb91e9939fbd06f8992f80b4a192e9"
FUNCTION_RVAS = ["0x43d0", "0x4250", "0x2ba0"]
TARGETS = ["linux-x64-asan", "windows-x64-wine"]
REPO = Path(__file__).resolve().parents[2]


def generate(state, binary):
    digest = file_sha256(binary)
    if digest != ZLZ_SHA256:
        raise ValueError("ZLZ64.dll differs from the reference used for this harness")
    functions = {}
    for line in (state / "modules" / digest / "functions.jsonl").open():
        row = json.loads(line)
        if row["rva"] in FUNCTION_RVAS:
            if row["status"] != "ok":
                raise ValueError("required function did not decompile")
            functions[row["rva"]] = row["c"]
    if set(functions) != set(FUNCTION_RVAS):
        raise ValueError("required function export is missing")
    bodies = "\n".join(functions[rva] for rva in FUNCTION_RVAS)
    # One backing allocation preserves aliases between byte arrays, individual
    # bytes, and uint32 tables. Independent DAT variables would silently break AES.
    symbols = sorted(set(re.findall(r"\bDAT_([0-9a-fA-F]+)\b", bodies)))
    data_start, data_end = 0x85000, 0x89500
    pe = pefile.PE(str(binary), fast_load=True)
    memory_image = pe.get_memory_mapped_image()
    data = memory_image[data_start:data_end].ljust(data_end - data_start, b"\0")
    declarations = []
    for symbol in symbols:
        rva = int(symbol, 16) - pe.OPTIONAL_HEADER.ImageBase
        if not data_start <= rva < data_end:
            raise ValueError(f"unexpected data dependency {symbol}")
        ctype = "uint" if rva == 0x850d8 or rva >= 0x85500 else "byte"
        if rva == 0x85200:
            ctype = "char"
        declarations.append(f"#define DAT_{symbol} (*({ctype} *)(recovered_data + {rva - data_start}))")
    pe.close()
    source = """#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t byte;
typedef uint32_t uint;
typedef uint32_t undefined4;
typedef int64_t longlong;
typedef uint64_t ulonglong;
_Alignas(16) static unsigned char recovered_data[] = {
""" + ",".join(str(value) for value in data) + "\n};\n" + "\n".join(declarations) + "\n" + bodies + """
int main(void) {
    unsigned char input[48];
    while (fread(input, 1, sizeof(input), stdin) == sizeof(input)) {
        uint strided_key[32] = {0};
        uint context[65] = {0};
        uint block[4];
        for (int i = 0; i < 8; i++) memcpy(&strided_key[i * 4], input + i * 4, 4);
        memcpy(block, input + 32, 16);
        FUN_180004250(strided_key, context + 1);
        FUN_180002ba0((longlong)(intptr_t)context, block);
        if (fwrite(block, 1, 16, stdout) != 16) return 2;
    }
    return ferror(stdin) || ferror(stdout);
}
"""
    # Windows CRT must use binary stdin/stdout; otherwise CR/LF and EOF translation
    # corrupt the vector stream. This is harness plumbing, not recovered logic.
    source = source.replace("int main(void) {", """#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
int main(void) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif""")
    return source, functions


def save_report(directory, source_path, functions, results):
    def stage(name):
        values = [r.get(name, "pending") for r in results]
        return "failed" if "failed" in values else "passed" if len(values) == len(TARGETS) and all(v == "passed" for v in values) else "pending"
    report = {"scope": "three recovered AES functions; not the complete client", "binary_sha256": ZLZ_SHA256,
              "source_sha256": file_sha256(source_path), "source": str(source_path.resolve()), "required_targets": TARGETS,
              "functions": [{"id": ZLZ_SHA256 + ":" + rva, "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
                             "compile_status": stage("compile_status"), "link_status": stage("link_status"),
                             "run_status": stage("run_status")} for rva, body in functions.items()], "results": results}
    staging = directory / "validation.json.partial"
    staging.write_text(json.dumps(report, indent=2) + "\n")
    staging.replace(directory / "validation.json")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=REPO / "downloads/cw_graph")
    parser.add_argument("--binary", type=Path, default=REPO.parent / "maplestorycw/appdata/ZLZ64.dll")
    parser.add_argument("--wine-prefix", type=Path, default=REPO / "downloads/cw_wine/prefix")
    args = parser.parse_args()
    directory = args.state / "validation" / "aes"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "validation.json").unlink(missing_ok=True)
    source, functions = generate(args.state, args.binary)
    source_path = directory / "recovered-aes.c"
    source_path.write_text(source)
    # FIPS-197 AES-256 example, the captured key/IV, and deterministic random cases.
    random_source = random.Random(0xC0DEC0DE)
    vectors = [(bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff")),
               (bytes.fromhex("0f0000001b000000c500000046000000f3000000be000000ff00000075000000"),
                bytes.fromhex("7156bc60") * 4)]
    vectors += [(random_source.randbytes(32), random_source.randbytes(16)) for _ in range(254)]
    inputs = b"".join(key + block for key, block in vectors)
    expected = b"".join(AES.new(key, AES.MODE_ECB).encrypt(block) for key, block in vectors)
    assert expected[:16].hex() == "8ea2b7ca516745bfeafc49904b496089"
    results = []
    for target, compiler, extra in [("linux-x64-asan", "gcc", ["-O1", "-fsanitize=address", "-fno-omit-frame-pointer"]),
                                    ("windows-x64-wine", "x86_64-w64-mingw32-gcc", ["-O2"])]:
        executable = directory / ("recovered-aes.exe" if target.startswith("windows") else "recovered-aes")
        object_path = directory / (target + ".o")
        executable.unlink(missing_ok=True)
        object_path.unlink(missing_ok=True)
        command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-parentheses", "-fno-strict-aliasing", "-fwrapv", *extra,
                   "-c", str(source_path.resolve()), "-o", str(object_path.resolve())]
        link_command = [compiler, *extra, str(object_path.resolve()), "-o", str(executable.resolve())]
        record = {"target": target, "compile_command": command, "link_command": link_command,
                  "compile_status": "pending", "link_status": "pending", "run_status": "pending"}
        results.append(record)
        phase = "compile_status"
        try:
            record["compiler"] = subprocess.check_output([compiler, "--version"], text=True).splitlines()[0]
            compiled = subprocess.run(command, capture_output=True, text=True)
            (directory / (target + "-compile.log")).write_text(compiled.stdout + compiled.stderr)
            if compiled.returncode:
                raise RuntimeError(f"compilation failed for {target}; see compile log")
            record["compile_status"] = "passed"
            phase = "link_status"
            linked = subprocess.run(link_command, capture_output=True, text=True)
            (directory / (target + "-link.log")).write_text(linked.stdout + linked.stderr)
            if linked.returncode:
                raise RuntimeError(f"linking failed for {target}; see link log")
            record.update({"link_status": "passed", "executable": str(executable.resolve()), "executable_sha256": file_sha256(executable)})
            phase = "run_status"
            if target.startswith("windows"):
                run = ["sudo", "-n", "ip", "netns", "exec", "maple-cw-local", "runuser", "-u", pwd.getpwuid(os.getuid()).pw_name,
                       "--", "env", "DISPLAY=:97", "WINEPREFIX=" + str(args.wine_prefix.resolve()), "WINEDEBUG=-all", "wine", str(executable.resolve())]
            else:
                run = [str(executable.resolve())]
            execution = subprocess.run(run, input=inputs, capture_output=True, timeout=120)
            (directory / (target + "-run.log")).write_bytes(execution.stderr)
            if execution.returncode or execution.stdout != expected:
                (directory / (target + "-actual.bin")).write_bytes(execution.stdout)
                (directory / "expected.bin").write_bytes(expected)
                raise RuntimeError(f"execution/output mismatch for {target}: exit {execution.returncode}, bytes {len(execution.stdout)}")
            clear = bytes(a ^ b for a, b in zip(bytes.fromhex("5447f32f442643"), execution.stdout[16:23]))
            if clear != bytes.fromhex("20000000000000"):
                raise RuntimeError("compiled AES does not reproduce the captured plaintext vector")
            record.update({"run_status": "passed", "vectors": len(vectors), "input_sha256": hashlib.sha256(inputs).hexdigest(),
                           "output_sha256": hashlib.sha256(execution.stdout).hexdigest(), "capture_vector": "passed"})
        except Exception as error:
            record[phase] = "failed"
            record["error"] = str(error)
            save_report(directory, source_path, functions, results)
            raise
    report = save_report(directory, source_path, functions, results)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
