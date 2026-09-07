from pydantic import BaseModel, EmailStr, Field
from typing import Dict, List, Literal, Optional

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=100)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class Branch(BaseModel):
    # One branch instruction as it appears on a single Python line's asm.
    #   mnemonic     — lowercased opcode with any size suffix (e.g. "jle", "jmp")
    #   conditional  — False for the jmp/jmpl unconditional family, else True
    #   direction    — forward | backward | self_loop | external | unknown
    #                  (forward = target below the branch — the if/else skip
    #                  pattern; backward = target above — a loop back-edge;
    #                  external = target label is not defined in this file, e.g.
    #                  a tail call; unknown = indirect target like `jmp *%eax`)
    #   target       — raw operand text (typically a label like ".L2"; empty
    #                  for a malformed no-operand line; starts with "*" for
    #                  an indirect target)
    mnemonic: str
    conditional: bool
    direction: str
    target: str


class LineMapping(BaseModel):
    c_lines: List[int]
    asm_lines: List[int]
    color: str
    # Cost analysis (transpile pipeline only). Number of real x86 instructions
    # this Python line compiled to, plus flags for expensive mnemonics
    # ("div", "mul", "call"). Default to the empty/zero case so the pyghidra
    # pipeline — which does not compute per-line cost — still validates.
    asm_count: int = 0
    flags: List[str] = Field(default_factory=list)
    # Instruction mix: how this line's asm splits across categories
    # (mem / compute / branch / call / stack / other). Zero categories are
    # omitted. Empty for the pyghidra pipeline, which computes no per-line mix.
    category_counts: Dict[str, int] = Field(default_factory=dict)
    # Register footprint: the canonical 32-bit x86 registers this Python line's
    # assembly touches, in stable display order (explicit operands plus implicit
    # ones like %edx:%eax on integer division). Empty for the pyghidra pipeline,
    # which computes no per-line footprint.
    registers: List[str] = Field(default_factory=list)
    # Stack frame map: the distinct %ebp-relative stack slots this Python line's
    # assembly touches (e.g. "-4(%ebp)", "8(%ebp)"), ordered by offset ascending
    # (locals first, then incoming args). Empty for the pyghidra pipeline, which
    # computes no per-line frame map.
    stack_slots: List[str] = Field(default_factory=list)
    # Memory traffic: how many memory reads (loads) and writes (stores) this
    # Python line's assembly performs, splitting the instruction-mix "mem" bucket
    # by direction. Only nonzero of {"loads", "stores"} are present. Empty for the
    # pyghidra pipeline, which computes no per-line memory traffic.
    memory_counts: Dict[str, int] = Field(default_factory=dict)
    # Branch flow: every branch instruction this Python line emits, in
    # occurrence order. Each entry names the mnemonic, whether it is
    # conditional, its direction relative to its source line (forward =
    # if/else branch-around, backward = loop back-edge), and the raw target
    # label. Empty for the pyghidra pipeline, which computes no per-line
    # branch map.
    branches: List[Branch] = Field(default_factory=list)


class Hotspot(BaseModel):
    py_line: int
    asm_count: int
    flags: List[str]


class CostSummary(BaseModel):
    total_instructions: int
    hotspots: List[Hotspot]
    # Program-wide instruction mix, same categories as LineMapping.category_counts.
    category_totals: Dict[str, int] = Field(default_factory=dict)


class RegisterSummary(BaseModel):
    # Program-wide register footprint: each canonical register mapped to the
    # number of instructions that reference it, in stable display order.
    register_totals: Dict[str, int] = Field(default_factory=dict)


class StackSummary(BaseModel):
    # Program-wide stack frame map.
    #   slot_totals  — each %ebp-relative slot label mapped to the number of
    #                  instructions that reference it, ordered by offset ascending.
    #   frame_slots  — number of distinct slots touched.
    #   locals_bytes — magnitude of the most-negative offset; a LOWER-BOUND
    #                  estimate of the local-variable region (the prologue's
    #                  `sub $N, %esp` carries no .loc and alignment padding is
    #                  not counted).
    slot_totals: Dict[str, int] = Field(default_factory=dict)
    frame_slots: int = 0
    locals_bytes: int = 0


class MemorySummary(BaseModel):
    # Program-wide memory traffic: the total number of memory reads (loads) and
    # writes (stores) across the whole program. Both keys are always present.
    memory_totals: Dict[str, int] = Field(default_factory=lambda: {"loads": 0, "stores": 0})


class BranchSummary(BaseModel):
    # Program-wide branch flow counts. Per-line branch entries live on
    # LineMapping.branches; this summary tallies them.
    #   total          — number of branch instructions overall
    #   conditional    — count where mnemonic is not jmp/jmpl
    #   unconditional  — count of jmp/jmpl
    #   forward        — target's asm line > source's (if/else branch-around)
    #   backward       — target's asm line < source's (loop back-edge)
    #   self_loop      — target's asm line == source's
    #   external       — target label is not defined in this asm file (tail call)
    #   unknown        — indirect target (`jmp *%eax`) or missing operand
    total: int = 0
    conditional: int = 0
    unconditional: int = 0
    forward: int = 0
    backward: int = 0
    self_loop: int = 0
    external: int = 0
    unknown: int = 0


class GlossaryEntry(BaseModel):
    # One distinct x86 mnemonic present in the compiled asm, with a plain-English
    # meaning. `base` is the canonical opcode family (e.g. "mov"), `category` is
    # the same six-bucket classification as the instruction-mix feature.
    mnemonic: str
    base: str
    category: str
    description: str

# Compile backend selectors:
#   transpile — the AST→C→gcc pipeline (default; supports per-line mapping)
#   pyghidra  — Nuitka → native binary → Ghidra disassembly + decompiled C
CompileMethod = Literal["transpile", "pyghidra"]

class CompileRequest(BaseModel):
    # Enforce the character cap at the schema layer so oversized bodies are
    # rejected before they are fully deserialized by the application logic.
    code: str = Field(max_length=10_000)
    method: CompileMethod = "transpile"

class CompileResponse(BaseModel):
    python_lines: List[str]
    c_code: str
    c_lines: List[str]
    asm_code: str
    asm_lines: List[str]
    line_map: Dict[int, LineMapping]
    # Present for the transpile pipeline; None for pyghidra (no per-line cost).
    cost_summary: Optional[CostSummary] = None
    # Present for the transpile pipeline; None for pyghidra (no per-line
    # register footprint).
    register_summary: Optional[RegisterSummary] = None
    # Present for the transpile pipeline; None for pyghidra (no per-line frame map).
    stack_summary: Optional[StackSummary] = None
    # Present for the transpile pipeline; None for pyghidra (no per-line memory
    # traffic).
    memory_summary: Optional[MemorySummary] = None
    # Present for the transpile pipeline; None for pyghidra (no per-line branch
    # map).
    branch_summary: Optional[BranchSummary] = None
    # Glossary of the distinct mnemonics in the compiled asm. Empty for the
    # pyghidra pipeline, which does not annotate its disassembly.
    asm_glossary: List[GlossaryEntry] = Field(default_factory=list)
