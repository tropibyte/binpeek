#!/bin/sh
# Compares binpeek's output with independent tools:
#   ELF: section names, addresses, offsets and sizes, DT_NEEDED and dynamic
#        symbol names against `readelf -W` (GNU binutils);
#   PE/COFF: sections, imports and exports against
#        `llvm-readobj --sections --coff-imports --coff-exports`.
#
# Linux only, and not part of ctest: it needs readelf, llvm-readobj and
# python3, and reads system files.
#
#   tools/compare_oracle.sh [BINPEEK] [FILE...]
#
# BINPEEK defaults to build/dev/binpeek. Without FILEs it checks /bin/ls,
# the system libc.so.6 and the fixtures in tests/data. Exit status 1 when
# anything differs.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
binpeek=${1:-$root/build/dev/binpeek}
[ $# -gt 0 ] && shift

for tool in readelf llvm-readobj python3; do
    command -v "$tool" > /dev/null || { echo "compare_oracle: $tool not found" >&2; exit 2; }
done
[ -x "$binpeek" ] || { echo "compare_oracle: $binpeek is not executable (build first)" >&2; exit 2; }

if [ $# -eq 0 ]; then
    libc=
    for candidate in /usr/lib/x86_64-linux-gnu/libc.so.6 /usr/lib64/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6; do
        if [ -z "$libc" ] && [ -f "$candidate" ]; then libc=$candidate; fi
    done
    set -- /bin/ls ${libc:+"$libc"} \
        "$root/tests/data/hello.elf" "$root/tests/data/sample.o" \
        "$root/tests/data/hello.exe" "$root/tests/data/greet.dll" "$root/tests/data/greet.obj"
fi

python3 -I - "$binpeek" "$@" << 'PYTHON'
import json
import re
import subprocess
import sys

binpeek, files = sys.argv[1], sys.argv[2:]
failures = 0


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, errors="replace").stdout


def peek(path, *options):
    return json.loads(run(binpeek, "--json", *options, path))


def compare(path, what, ours, theirs):
    global failures
    if ours == theirs:
        return True
    failures += 1
    print(f"MISMATCH {path}: {what}")
    for i, (a, b) in enumerate(zip(ours, theirs)):
        if a != b:
            print(f"  first difference at {i}: binpeek {a!r}, oracle {b!r}")
            break
    else:
        print(f"  binpeek has {len(ours)} entries, oracle {len(theirs)}")
    return False


def readelf_sections(path):
    sections = []
    for line in run("readelf", "-W", "-S", path).splitlines():
        m = re.match(r"\s*\[\s*(\d+)\]\s(.*)$", line)
        if not m:
            continue
        fields = m.group(2).split()
        if int(m.group(1)) == 0:
            fields.insert(0, "")  # the null section has no name
        sections.append((fields[0], int(fields[2], 16), int(fields[3], 16), int(fields[4], 16)))
    return sections


def readelf_needed(path):
    return re.findall(r"\(NEEDED\)\s+Shared library: \[(.*)\]", run("readelf", "-W", "-d", path))


def readelf_dynsyms(path):
    names = []
    for line in run("readelf", "-W", "--dyn-syms", path).splitlines():
        m = re.match(r"\s*\d+:\s", line)
        if not m:
            continue
        fields = line.split()
        name = fields[7] if len(fields) > 7 else ""
        names.append(name.split("@")[0])  # readelf appends symbol versions
    return names


def check_elf(path):
    data = peek(path, "-S", "--dyn-syms", "-H")
    ours = [(s["name"], s["address"], s["offset"], s["size"]) for s in data["sections"]]
    ok = compare(path, "sections (name, address, offset, size)", ours, readelf_sections(path))
    ok &= compare(path, "DT_NEEDED", data["header"]["needed"], readelf_needed(path))
    ok &= compare(path, "dynamic symbol names", [s["name"] for s in data["dynamic_symbols"]], readelf_dynsyms(path))
    if ok:
        print(f"OK  {path}: {len(ours)} sections, {len(data['header']['needed'])} DT_NEEDED, "
              f"{len(data['dynamic_symbols'])} dynamic symbols")


def llvm_blocks(text, kind):
    """The 'Key: value' lines of each top-level `kind {` block."""
    blocks, current, depth = [], None, 0
    for line in text.splitlines():
        stripped = line.strip()
        if current is None:
            if stripped == kind + " {":
                current, depth = [], 1
            continue
        if stripped.endswith("{"):
            depth += 1
        elif stripped == "}":
            depth -= 1
            if depth == 0:
                blocks.append(current)
                current = None
                continue
        if depth == 1 and ": " in stripped:
            current.append(tuple(stripped.split(": ", 1)))
        elif depth == 1 and stripped.endswith(":"):
            current.append((stripped[:-1], ""))
    return blocks


def check_pe(path):
    data = peek(path, "-S", "-i", "-e")
    text = run("llvm-readobj", "--sections", "--coff-imports", "--coff-exports", path)

    theirs = []
    for block in llvm_blocks(text, "Section"):
        f = dict(block)
        theirs.append((f["Name"].rsplit(" (", 1)[0], int(f["VirtualSize"], 0), int(f["VirtualAddress"], 0),
                       int(f["RawDataSize"], 0), int(f["PointerToRawData"], 0)))
    ours = [(s["name"], s["virtual_size"], s["virtual_address"], s["raw_size"], s["raw_offset"])
            for s in data["sections"]]
    ok = compare(path, "sections (name, virtual size and address, raw size and offset)", ours, theirs)

    theirs = []
    for block in llvm_blocks(text, "Import"):
        dll = dict(block)["Name"]
        for key, value in block:
            if key == "Symbol":
                name, number = re.match(r"(.*) \((\d+)\)$", value).groups()
                theirs.append((dll, name, int(number)))
    ours = [(d["dll"], f.get("name", ""), f["hint"] if "name" in f else f["ordinal"])
            for d in data["imports"] for f in d["functions"]]
    ok &= compare(path, "imports (DLL, name, hint or ordinal)", ours, theirs)

    theirs = []
    for block in llvm_blocks(text, "Export"):
        f = dict(block)
        target = f.get("ForwardedTo") or int(f["RVA"], 0)
        if target == 0 and not f.get("Name"):
            continue  # an unused slot; binpeek leaves these out
        theirs.append((int(f["Ordinal"]), f.get("Name", ""), target))
    exports = data["exports"]["functions"] if data["exports"] else []
    ours = [(e["ordinal"], e["name"] or "", e["forwarder"] or e["rva"]) for e in exports]
    ok &= compare(path, "exports (ordinal, name, RVA or forwarder)", ours, theirs)
    if ok:
        print(f"OK  {path}: {len(data['sections'])} sections, {len(ours)} exports, "
              f"{sum(len(d['functions']) for d in data['imports'])} imports from {len(data['imports'])} DLLs")


for path in files:
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x7fELF":
        check_elf(path)
    else:
        check_pe(path)

sys.exit(1 if failures else 0)
PYTHON
