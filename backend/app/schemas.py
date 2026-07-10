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
    # Cost-lens convenience counts. Defaulted so the pyghidra backend (which
    # returns an empty line_map and no counts) still validates unchanged.
    c_count: int = 0
    asm_count: int = 0

class LineMetric(BaseModel):
    c_count: int
    asm_count: int

class ExpansionMetrics(BaseModel):
    """Per-line assembly-expansion summary ("cost lens"). Populated by the
    transpile backend; null for pyghidra, which does not build a line map."""
    total_asm_instructions: int
    total_c_lines: int
    line_count: int
    mean_asm_per_line: float
    max_asm_line: Optional[int] = None
    hotspots: List[int]
    hotspot_threshold: int
    per_line: Dict[int, LineMetric]

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
    # Assembly-expansion "cost lens" — present for the transpile backend, null
    # for pyghidra (which returns no per-line map).
    metrics: Optional[ExpansionMetrics] = None
