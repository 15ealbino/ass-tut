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
