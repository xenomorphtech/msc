#!/usr/bin/env python3
"""Rebuild bounded integer leaf functions and compare to mapped original code.

Candidates have primitive value arguments, no calls, no global/indirect memory,
and no backward or external branches. Execution is local to the Wine namespace.
"""
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

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from capstone.x86_const import X86_REG_RIP, X86_REG_RSP, X86_REG_RBP

from build import HERE, REPO, MAIN_SHA, file_sha256

TYPES = "byte|char|sbyte|short|ushort|int|uint|longlong|ulonglong|bool|undefined1|undefined2|undefined4|undefined8"
HEADER = """#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t byte, undefined1;
typedef int8_t sbyte;
typedef uint16_t ushort, undefined2;
typedef uint32_t uint, undefined4;
typedef uint64_t ulonglong, undefined8;
typedef int64_t longlong;
"""


def discover(state, binary):
    if file_sha256(binary) != MAIN_SHA:
        raise ValueError("reference hash changed")
    pe = pefile.PE(str(binary), fast_load=True)
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    signature = re.compile(r"\n(" + TYPES + r")\s+(FUN_[0-9a-f]+)\(([^)]*)\)\s*\n?\s*\{")
    allowed = {"mov", "movabs", "movsx", "movsxd", "movzx", "lea", "add", "sub", "imul", "mul", "inc", "dec", "neg", "not",
               "xor", "and", "or", "shl", "sal", "shr", "sar", "rol", "ror", "shld", "shrd", "bswap", "bt", "btc", "btr", "bts",
               "cmp", "test", "ret", "push", "pop", "nop", "cdqe", "cdq", "cqo", "adc", "sbb", "xchg", "movsxd"}
    candidates = []
    for line in (state / "modules" / MAIN_SHA / "functions.jsonl").open():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        code = row.get("c") or ""
        match = signature.search(code)
        if row["status"] != "ok" or not match or "*" in match[3] or "[" in code or re.search(r"\*\s*\(", code) or len(row["ranges"]) != 1:
            continue
        if re.search(r"\b(?:in_|unaff_|extraout_)\w+", code):
            continue  # The register/return ABI must be recovered first.
        arguments = match[3].split(",") if match[3] != "void" else []
        if len(arguments) > 4 or any(not re.fullmatch(r"\s*(" + TYPES + r")\s+\w+\s*", arg) for arg in arguments):
            continue
        calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code)) - {match[2], "if", "for", "while", "switch", "sizeof", *TYPES.split("|")}
        if calls:
            continue
        start, end = [int(part, 16) for part in row["ranges"][0]]
        if end - start < 13 or end - start > 512:
            continue
        instructions = list(cs.disasm(pe.get_data(start, end - start + 1), start))
        valid = sum(i.size for i in instructions) == end - start + 1
        for instruction in instructions:
            if not (instruction.mnemonic in allowed or instruction.mnemonic.startswith(("cmov", "set")) or instruction.group(CS_GRP_JUMP)):
                valid = False
            if instruction.group(CS_GRP_JUMP) and (len(instruction.operands) != 1 or instruction.operands[0].type != CS_OP_IMM or not instruction.address < instruction.operands[0].imm <= end):
                valid = False
            for operand in instruction.operands:
                if operand.type == CS_OP_REG and instruction.reg_name(operand.reg).startswith(("xmm", "ymm", "zmm", "st")):
                    valid = False
                if operand.type == CS_OP_MEM:
                    if operand.mem.base == X86_REG_RIP:
                        valid = False
                    if instruction.mnemonic != "lea" and (operand.mem.base not in [X86_REG_RSP, X86_REG_RBP] or operand.mem.index or operand.mem.segment):
                        valid = False
        if valid:
            candidates.append({**row, "return_type": match[1], "symbol": match[2],
                               "argument_types": [a.strip().split()[0] for a in arguments]})
    pe.close()
    return candidates


def driver(candidates):
    cases = []
    addresses = []
    for index, row in enumerate(candidates):
        types = row["argument_types"]
        signature = ",".join(types) or "void"
        arguments = ",".join(f"({kind})a[{i}]" for i, kind in enumerate(types))
        mask = " & 0xffU" if row.get("return_bits") == 8 else ""
        cases.append(f"case {index}: return ((uint64_t)(({row['return_type']} (*)({signature}))entry)({arguments})){mask};")
        addresses.append(f"(void *){row['symbol']}")
    return """
#ifndef CW_LEAF_DLL
#pragma pack(push, 1)
struct Record { uint32_t index; uint64_t args[4]; uint64_t expected; };
#pragma pack(pop)
static uint64_t invoke(unsigned index, void *entry, const uint64_t *a) {
  switch(index) {
""" + "\n".join(cases) + "\n default: abort(); }\n}\n" + """
#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
""" + "static const size_t rvas[] = {" + ",".join(r["rva"] for r in candidates) + "};\n" + "static const char *symbols[] = {" + ",".join(json.dumps(r["symbol"]) for r in candidates) + "};\n" + """
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  HMODULE original = LoadLibraryExA(argv[1], NULL, DONT_RESOLVE_DLL_REFERENCES);
  HMODULE rebuilt = LoadLibraryA(argv[2]);
  if (!original || !rebuilt) { fprintf(stderr, "load failed %lu\\n", (unsigned long)GetLastError()); return 3; }
  FILE *oracle = fopen(argv[3], "wb");
  if (!oracle) return 4;
  _setmode(_fileno(stdin), _O_BINARY);
  struct Record record;
  unsigned failures = 0;
  while (fread(&record, 1, 36, stdin) == 36) {
    if (record.index >= sizeof(rvas) / sizeof(*rvas)) return 5;
    void *entry = (void *)GetProcAddress(rebuilt, symbols[record.index]);
    if (!entry) return 6;
    record.expected = invoke(record.index, (unsigned char *)original + rvas[record.index], record.args);
    uint64_t actual = invoke(record.index, entry, record.args);
    if (actual != record.expected) {
      printf("{\\"index\\":%u,\\"status\\":\\"failed\\",\\"expected\\":%llu,\\"actual\\":%llu}\\n", record.index,
             (unsigned long long)record.expected, (unsigned long long)actual);
      failures++;
    }
    if (fwrite(&record, 1, sizeof(record), oracle) != sizeof(record)) return 7;
  }
  if (fclose(oracle) || ferror(stdin)) return 8;
  return failures ? 1 : 0;
}
#else
""" + "static void *entries[] = {" + ",".join(addresses) + "};\n" + """
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *oracle = fopen(argv[1], "rb");
  if (!oracle) return 3;
  struct Record record;
  unsigned failures = 0;
  while (fread(&record, 1, sizeof(record), oracle) == sizeof(record)) {
    if (record.index >= sizeof(entries) / sizeof(*entries)) return 4;
    uint64_t actual = invoke(record.index, entries[record.index], record.args);
    if (actual != record.expected) {
      printf("{\\"index\\":%u,\\"status\\":\\"failed\\",\\"expected\\":%llu,\\"actual\\":%llu}\\n", record.index,
             (unsigned long long)record.expected, (unsigned long long)actual);
      failures++;
    }
  }
  return failures || ferror(oracle) || fclose(oracle);
}
#endif
#endif
"""


def runtime(candidates, binary):
    pe = pefile.PE(str(binary), fast_load=True)
    preimages = [pe.get_data(int(row["rva"], 16), 32) for row in candidates]
    pe.close()
    prefix = "#define CW_LEAF_COUNT " + str(len(candidates)) + "\n#if defined(_WIN32) && defined(CW_LEAF_DLL)\n"
    prefix += "static const size_t cw_leaf_rvas[] = {" + ",".join(row["rva"] for row in candidates) + "};\n"
    prefix += "static const unsigned char cw_leaf_preimages[][32] = {" + ",".join("{" + ",".join(map(str, data)) + "}" for data in preimages) + "};\n#endif\n"
    wrappers, targets = [], []
    for index, row in enumerate(candidates):
        arguments = ",".join(f"{kind} a{i}" for i, kind in enumerate(row["argument_types"])) or "void"
        values = ",".join(f"a{i}" for i in range(len(row["argument_types"])))
        name = "cw_leaf_entry_" + str(index)
        wrappers.append(f"static {row['return_type']} {name}({arguments}) {{ {row['return_type']} result = {row['symbol']}({values}); cw_leaf_called({index}); return result; }}")
        targets.append("(void *)" + name)
    wrappers.append("static void *cw_leaf_targets[] = {" + ",".join(targets) + "};")
    return prefix + (HERE / "leaf_runtime.c").read_text().replace("/* CW_WRAPPERS */", "\n".join(wrappers)), preimages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=REPO / "downloads/cw_graph")
    parser.add_argument("--binary", type=Path, default=REPO.parent / "maplestorycw/appdata/MapleStory.exe")
    args = parser.parse_args()
    directory = args.state.resolve() / "validation/leaf-core"
    directory.mkdir(parents=True, exist_ok=True)
    candidates = discover(args.state, args.binary)
    if not candidates:
        raise ValueError("no eligible functions")
    # undefined8 is Ghidra's unknown-width return, not proof that all RAX bits
    # belong to the native contract. Narrow only with explicit native caller
    # evidence and a recovered Boolean predicate; never normalize arbitrary
    # failed outputs. Keep the first failed wide-return run in attempts/.
    contracts_path = HERE / "leaf-abi.json"
    if contracts_path.exists():
        contracts = json.loads(contracts_path.read_text())
        if contracts["reference_sha256"] != MAIN_SHA:
            raise ValueError("ABI evidence belongs to another reference")
        pe = pefile.PE(str(args.binary), fast_load=True)
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.detail = True
        for row in candidates:
            contract = contracts["functions"].get(row["rva"])
            if not contract:
                continue
            returns = set(re.findall(r"\breturn\s+([^;]+);", row["c"]))
            if row["return_type"] != "undefined8" or not returns <= {"0", "1"} or contract["return_bits"] != 8 or not contract["evidence"]:
                raise ValueError("ABI narrowing is restricted to evidenced Boolean predicates")
            for evidence in contract["evidence"]:
                site = int(evidence["site"], 16)
                data = pe.get_data(site, 32)
                if hashlib.sha256(data).hexdigest() != evidence["bytes_sha256"]:
                    raise ValueError("native caller preimage changed")
                instructions = list(cs.disasm(data, site))
                first = instructions[0]
                if first.mnemonic != "call" or first.operands[0].type != CS_OP_IMM or first.operands[0].imm != int(row["rva"], 16):
                    raise ValueError("ABI evidence is not a direct call to the recovered function")
                consumed = False
                for instruction in instructions[1:]:
                    read, written = instruction.regs_access()
                    reads = {instruction.reg_name(register) for register in read}
                    writes = {instruction.reg_name(register) for register in written}
                    if reads & {"rax", "eax", "ax", "ah", "al"}:
                        if reads & {"rax", "eax", "ax", "ah"} or "al" not in reads:
                            raise ValueError("a native caller consumes more than AL")
                        consumed = True
                        break
                    if writes & {"rax", "eax", "ax", "ah", "al"} or instruction.mnemonic in ("call", "ret", "jmp"):
                        break
                if not consumed:
                    raise ValueError("no low-byte consumption in caller evidence")
            row["return_bits"] = 8
            row["abi_evidence"] = str(contracts_path)
        pe.close()
    (directory / "candidates.json").write_text(json.dumps([{k: v for k, v in r.items() if k != "c"} for r in candidates], indent=2) + "\n")
    source = directory / "leaf-core.c"
    runtime_source, preimages = runtime(candidates, args.binary)
    source.write_text(HEADER + "\n".join(r["c"] for r in candidates) + runtime_source + driver(candidates))
    rng = random.Random(0x4c454146)
    vector_count = []
    with (directory / "inputs.bin").open("wb") as stream:
        for index, row in enumerate(candidates):
            values = set(range(256)) | {0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff}
            for literal in re.findall(r"\b(?:0x[0-9a-fA-F]+|[0-9]+)\b", row["c"]):
                value = int(literal, 16 if literal.startswith("0x") else 10)
                values.update((value - 1 & (2**64 - 1), value & (2**64 - 1), value + 1 & (2**64 - 1)))
            vectors = [(value,) * 4 for value in sorted(values)]
            for argument in range(len(row["argument_types"])):
                for value in sorted(values):
                    for baseline in (0, 1, 2**64 - 1):
                        vector = [baseline] * 4
                        vector[argument] = value
                        vectors.append(tuple(vector))
            vectors += [tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(1024)]
            vector_count.append(len(vectors))
            for vector in vectors:
                stream.write(struct.pack("<IQQQQ", index, *vector))
    results = []
    flags = ["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-Wno-parentheses", "-Wno-unused-parameter", "-fno-strict-aliasing", "-fwrapv"]
    report = {"scope": "bounded integer leaf functions; original-code oracle and optional hybrid replacement", "binary_sha256": MAIN_SHA,
              "source": str(source), "source_sha256": file_sha256(source),
              "required_targets": ["windows-x64-leaf-dll", "windows-x64-original-oracle", "linux-x64-asan-oracle"],
              "functions": [{"id": row["id"], "body_sha256": hashlib.sha256(row["c"].encode()).hexdigest(),
                             **({"return_bits": 8, "abi_evidence": str(contracts_path)} if row.get("return_bits") == 8 else {})}
                            for row in candidates], "results": results}
    def save():
        staging = directory / "validation.json.partial"
        staging.write_text(json.dumps(report, indent=2) + "\n")
        staging.replace(directory / "validation.json")
    for target, compiler, extra, artifact in [
        (report["required_targets"][0], "x86_64-w64-mingw32-gcc", ["-DCW_LEAF_DLL"], directory / "leaf-core.dll"),
        (report["required_targets"][1], "x86_64-w64-mingw32-gcc", [], directory / "leaf-oracle.exe"),
        (report["required_targets"][2], "gcc", ["-fsanitize=address", "-fno-omit-frame-pointer"], directory / "leaf-oracle")]:
        obj = directory / (target + ".o")
        record = {"target": target, "compile_status": "pending", "link_status": "pending", "run_status": "pending"}
        results.append(record)
        command = [compiler, *flags, *extra, "-c", str(source), "-o", str(obj)]
        record["compile_command"] = command
        compiled = subprocess.run(command, capture_output=True)
        (directory / (target + "-compile.log")).write_bytes(compiled.stdout + compiled.stderr)
        record["compile_status"] = "passed" if compiled.returncode == 0 else "failed"
        save()
        if compiled.returncode:
            raise RuntimeError(f"compile failed: {target}; see log")
        link = [compiler, *extra, *(["-shared", "-Wl,--export-all-symbols"] if target.endswith("dll") else []), str(obj), "-o", str(artifact)]
        record["link_command"] = link
        linked = subprocess.run(link, capture_output=True)
        (directory / (target + "-link.log")).write_bytes(linked.stdout + linked.stderr)
        record["link_status"] = "passed" if linked.returncode == 0 else "failed"
        if linked.returncode:
            save()
            raise RuntimeError(f"link failed: {target}")
        record.update(executable=str(artifact), executable_sha256=file_sha256(artifact))
        save()
    winpath = lambda path: "Z:" + str(path.resolve()).replace("/", "\\")
    command = ["sudo", "-n", "ip", "netns", "exec", "maple-cw-local", "runuser", "-u", pwd.getpwuid(os.getuid()).pw_name,
               "--", "env", "DISPLAY=:97", "WINEPREFIX=" + str(REPO / "downloads/cw_wine/prefix"), "WINEDEBUG=-all", "wine",
               str(directory / "leaf-oracle.exe"), winpath(args.binary), winpath(directory / "leaf-core.dll"), winpath(directory / "oracle.bin")]
    with (directory / "inputs.bin").open("rb") as inputs:
        execution = subprocess.run(command, stdin=inputs, capture_output=True, timeout=180)
    (directory / "windows-run.log").write_bytes(execution.stdout + execution.stderr)
    status = "passed" if execution.returncode == 0 else "failed"
    for result in results[:2]:
        result.update(run_status=status, functions=len(candidates), vectors=sum(vector_count), oracle_sha256=file_sha256(directory / "oracle.bin") if (directory / "oracle.bin").exists() else None)
    save()
    expected_size = sum(vector_count) * 44
    if execution.returncode not in (0, 1) or not (directory / "oracle.bin").exists() or (directory / "oracle.bin").stat().st_size != expected_size:
        raise RuntimeError(f"original/DLL oracle did not finish: exit={execution.returncode}; see windows-run.log")
    windows_failed = {json.loads(line)["index"] for line in execution.stdout.decode().splitlines() if line.startswith('{"index":')}
    for result in results[:2]:
        result["function_results"] = {row["id"]: {"run_status": "failed" if i in windows_failed else "passed", "vectors": vector_count[i]}
                                      for i, row in enumerate(candidates)}
    save()
    execution = subprocess.run([str(directory / "leaf-oracle"), str(directory / "oracle.bin")], capture_output=True, timeout=180)
    (directory / "linux-run.log").write_bytes(execution.stdout + execution.stderr)
    results[2].update(run_status="passed" if execution.returncode == 0 else "failed", functions=len(candidates), vectors=sum(vector_count),
                      oracle_sha256=file_sha256(directory / "oracle.bin"))
    if execution.returncode in (0, 1):
        linux_failed = {json.loads(line)["index"] for line in execution.stdout.decode().splitlines() if line.startswith('{"index":')}
        results[2]["function_results"] = {row["id"]: {"run_status": "failed" if i in linux_failed else "passed", "vectors": vector_count[i]}
                                           for i, row in enumerate(candidates)}
    else:
        linux_failed = set(range(len(candidates)))
    save()
    failed = windows_failed | linux_failed
    print(json.dumps({"functions": len(candidates), "passed": len(candidates) - len(failed), "failed": len(failed),
                      "vectors": sum(vector_count), "report": str(directory / "validation.json")}, indent=2))
    if failed:
        raise SystemExit(1)
    manifest = {"reference_sha256": MAIN_SHA, "dll": str(directory / "leaf-core.dll"),
                "dll_sha256": file_sha256(directory / "leaf-core.dll"), "validation": str(directory / "validation.json"),
                "functions": [{"rva": row["rva"], "preimage": data.hex()} for row, data in zip(candidates, preimages)]}
    (directory / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
