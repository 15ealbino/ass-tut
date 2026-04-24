from pydantic import BaseModel, EmailStr, Field
from typing import Dict, List

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

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
    code: str

class CompileResponse(BaseModel):
    python_lines: List[str]
    c_code: str
    c_lines: List[str]
    asm_code: str
    asm_lines: List[str]
    line_map: Dict[int, LineMapping]
