"""
Tests for the assembly instruction-glossary feature (feat/asm-glossary).

Where the cost flags say *how much* and the instruction mix says *what kind*,
the glossary answers the most elementary question a learner has on opening the
ASM pane: *what does each of these mnemonics mean?* `build_asm_glossary` scans
the compiled asm and returns one plain-English entry per DISTINCT mnemonic.

Two layers, mirroring test_instruction_mix.py:
  * Pure-function unit tests for `build_asm_glossary` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the glossary reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.asm_glossary import _GLOSSARY_PREFIXES, build_asm_glossary
from app.compile import _CATEGORY_ORDER, classify_category

# asyncio_mode=auto (pytest.ini) auto-detects the async e2e tests; the sync unit
# tests below need no marker.


# ─── gcc availability guard (mirrors the real pipeline's requirements) ───────

def _gcc_m32_available() -> bool:
    if shutil.which("gcc") is None:
        return False
    try:
        r = subprocess.run(
            ["gcc", "-S", "-O0", "-m32", "-x", "c", "-o", "/dev/null", "-"],
            input='#include <stdio.h>\nint main(){printf("");return 0;}',
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


needs_gcc = pytest.mark.skipif(
    not _gcc_m32_available(), reason="gcc with -m32 support not available"
)


# A small but representative slab of real gcc -O0 -m32 output, reused across the
# pure-function tests: labels, directives, blanks, a duplicate mnemonic, an
# expensive divide (with its cltd setup), a branch, a call, and an unknown op.
_SAMPLE_ASM = [
    "\t.file\t\"code.c\"",           # directive → skipped
    "main:",                          # label → skipped
    "\tpushl\t%ebp",                  # stack
    "\tmovl\t%esp, %ebp",             # mem
    "",                               # blank → skipped
    ".L2:",                           # label → skipped
    "\timull\t%edx, %eax",            # compute
    "\tcltd",                         # mem
    "\tidivl\t%ecx",                  # compute
    "\tcmpl\t$2, %eax",               # branch
    "\tjle\t.L3",                     # branch
    "\tcall\thelper",                 # call
    "\tmovl\t%eax, -4(%ebp)",         # mem (duplicate movl)
    "\tleave",                        # call (must NOT be read as lea/mem)
    "\tret",                          # call
    "\twibblezorp\t%eax",             # unknown → other
]


# ─── Unit: build_asm_glossary ────────────────────────────────────────────────

def test_glossary_entry_shape_is_complete():
    for entry in build_asm_glossary(_SAMPLE_ASM):
        assert set(entry) == {"mnemonic", "base", "category", "description"}
        assert entry["mnemonic"] and entry["description"]


def test_glossary_deduplicates_mnemonics():
    # movl appears twice in the sample; it must produce exactly one entry.
    mnemonics = [e["mnemonic"] for e in build_asm_glossary(_SAMPLE_ASM)]
    assert mnemonics.count("movl") == 1
    assert len(mnemonics) == len(set(mnemonics))


def test_glossary_excludes_labels_directives_and_blanks():
    mnemonics = {e["mnemonic"] for e in build_asm_glossary(_SAMPLE_ASM)}
    # No directive/label/blank leaks in.
    assert not any(m.startswith(".") for m in mnemonics)
    assert "main:" not in mnemonics and ".l2:" not in mnemonics
    assert "" not in mnemonics
    # The real instructions are all present.
    assert {"pushl", "movl", "imull", "idivl", "cmpl", "jle", "call", "ret"} <= mnemonics


def test_glossary_category_always_matches_classify_category():
    # The glossary must never derive its own category — it delegates to the
    # single source of truth so it can't drift from the instruction-mix feature.
    for entry in build_asm_glossary(_SAMPLE_ASM):
        assert entry["category"] == classify_category(entry["mnemonic"])


def test_glossary_keeps_unknown_mnemonic_as_other_with_fallback():
    entry = next(
        e for e in build_asm_glossary(_SAMPLE_ASM) if e["mnemonic"] == "wibblezorp"
    )
    assert entry["category"] == "other"
    assert entry["base"] == "wibblezorp"          # base falls back to the mnemonic
    assert "wibblezorp" in entry["description"]   # generic fallback description


def test_glossary_is_sorted_by_category_then_mnemonic():
    entries = build_asm_glossary(_SAMPLE_ASM)
    keys = [(_CATEGORY_ORDER.get(e["category"], 99), e["mnemonic"]) for e in entries]
    assert keys == sorted(keys)


def test_glossary_leave_is_not_shadowed_by_lea():
    # "leave".startswith("lea") is True, so a mis-ordered table would describe
    # `leave` as load-effective-address. It must resolve to the call/frame entry.
    entry = next(e for e in build_asm_glossary(["\tleave"]) if e["mnemonic"] == "leave")
    assert entry["base"] == "leave"
    assert entry["category"] == "call"
    assert "frame" in entry["description"]


def test_glossary_distinguishes_widening_moves_from_plain_mov():
    entries = {e["mnemonic"]: e for e in build_asm_glossary(
        ["\tmovl\t%eax, %ebx", "\tmovzbl\t%al, %eax", "\tmovsbl\t%al, %eax"]
    )}
    assert entries["movl"]["base"] == "mov"
    assert entries["movzbl"]["base"] == "movz"
    assert entries["movsbl"]["base"] == "movs"
    # All three are still memory-traffic.
    assert {e["category"] for e in entries.values()} == {"mem"}


def test_glossary_empty_input_is_empty_list():
    assert build_asm_glossary([]) == []
    assert build_asm_glossary(["\t.text", "main:", ""]) == []


def test_no_glossary_prefix_is_shadowed_by_an_earlier_one():
    # Guardrail against the ordering hazard the table's own comment warns about
    # (e.g. `mov` shadowing `movz`, `lea` shadowing `leave`): every prefix must
    # be *reachable*. A mnemonic formed from a prefix must resolve to that same
    # prefix as its base — if it resolves to an earlier one, that entry is dead.
    for prefix, _desc in _GLOSSARY_PREFIXES:
        sample = prefix + "l"  # a plausible size-suffixed member of the family
        entry = next(
            e for e in build_asm_glossary([f"\t{sample}\t%eax"])
            if e["mnemonic"] == sample
        )
        assert entry["base"] == prefix, (
            f"prefix {prefix!r} is shadowed by {entry['base']!r}"
        )


# ─── End-to-end: /compile carries the glossary ───────────────────────────────

@needs_gcc
async def test_compile_response_includes_asm_glossary(client):
    r = await client.post("/compile", json={"code": "x = 6\ny = x * 7\n"})
    assert r.status_code == 200
    glossary = r.json()["asm_glossary"]
    assert isinstance(glossary, list) and glossary
    mnemonics = [e["mnemonic"] for e in glossary]
    # Distinct, well-formed entries with valid categories.
    assert len(mnemonics) == len(set(mnemonics))
    for e in glossary:
        assert set(e) == {"mnemonic", "base", "category", "description"}
        assert e["category"] in {"mem", "compute", "branch", "call", "stack", "other"}
        assert e["description"]


@needs_gcc
async def test_compile_glossary_explains_the_multiply(client):
    # a * b emits an imul → the glossary must carry an imul* entry in 'compute'.
    r = await client.post("/compile", json={"code": "def f(a, b):\n    return a * b\n"})
    assert r.status_code == 200
    glossary = r.json()["asm_glossary"]
    imul = [e for e in glossary if e["base"] == "imul"]
    assert imul and imul[0]["category"] == "compute"


@needs_gcc
async def test_compile_glossary_entries_match_classify_category(client):
    # The category surfaced in the API is exactly classify_category — end to end.
    r = await client.post("/compile", json={"code": "x = 0\nfor i in range(5):\n    x = x + i\n"})
    assert r.status_code == 200
    for e in r.json()["asm_glossary"]:
        assert e["category"] == classify_category(e["mnemonic"])
