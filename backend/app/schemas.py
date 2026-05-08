from pydantic import BaseModel, EmailStr, Field
from typing import Dict, List

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

class CompileRequest(BaseModel):
    # Enforce the character cap at the schema layer so oversized bodies are
    # rejected before they are fully deserialized by the application logic.
    code: str = Field(max_length=10_000)

class CompileResponse(BaseModel):
    python_lines: List[str]
    c_code: str
    c_lines: List[str]
    asm_code: str
    asm_lines: List[str]
    line_map: Dict[int, LineMapping]
