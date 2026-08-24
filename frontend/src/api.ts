const BASE = '/api'

let _token: string | null = null

export function setToken(t: string) { _token = t }
export function clearToken() { _token = null }
export function hasToken() { return !!_token }

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (_token) headers['Authorization'] = `Bearer ${_token}`
  const res = await fetch(`${BASE}${path}`, { ...options, headers })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? 'Request failed')
  }
  return res.json()
}

export interface AuthResponse { access_token: string; token_type: string }

export function register(email: string, password: string) {
  return request<AuthResponse>('/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) })
}

export function login(email: string, password: string) {
  return request<AuthResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
}

export interface LineMapping {
  c_lines: number[]
  asm_lines: number[]
  color: string
  // Cost analysis (transpile pipeline). Number of real x86 instructions this
  // Python line compiled to, plus flags for expensive mnemonics.
  asm_count?: number
  flags?: string[]
  // Instruction mix: how this line's asm splits across categories
  // (mem / compute / branch / call / stack / other). Zero categories omitted.
  category_counts?: Record<string, number>
  // Register footprint: canonical 32-bit x86 registers this line's asm touches,
  // in stable display order (includes implicit regs like edx:eax on division).
  registers?: string[]
  // Stack frame map: the distinct %ebp-relative stack slots this line's asm
  // touches (e.g. "-4(%ebp)", "8(%ebp)"), ordered by offset (locals then args).
  stack_slots?: string[]
  // Memory traffic: how many memory reads (loads) and writes (stores) this
  // line's asm performs. Only nonzero of {loads, stores} are present.
  memory_counts?: Record<string, number>
  // Branch flow: every branch instruction this Python line emits, in
  // occurrence order. Each entry names the mnemonic, whether it is
  // conditional, its direction relative to its source line (forward =
  // if/else branch-around, backward = loop back-edge), and the raw target.
  branches?: Branch[]
}

export interface Branch {
  // One branch instruction on a Python line's asm.
  //   mnemonic     — lowercased opcode with any size suffix ("jle", "jmp")
  //   conditional  — false for jmp/jmpl, true for every j*/loop* conditional
  //   direction    — "forward" | "backward" | "self_loop" | "external" | "unknown"
  //   target       — raw operand text; ".L2", empty for a malformed line,
  //                  or "*%eax" for an indirect target
  mnemonic: string
  conditional: boolean
  direction: 'forward' | 'backward' | 'self_loop' | 'external' | 'unknown'
  target: string
}

export interface Hotspot { py_line: number; asm_count: number; flags: string[] }

export interface CostSummary {
  total_instructions: number
  hotspots: Hotspot[]
  // Program-wide instruction mix (same categories as LineMapping.category_counts).
  category_totals?: Record<string, number>
}

export interface RegisterSummary {
  // Program-wide register footprint: each canonical register mapped to the
  // number of instructions that reference it, in stable display order.
  register_totals: Record<string, number>
}

export interface StackSummary {
  // Program-wide stack frame map: each %ebp-relative slot label mapped to the
  // number of instructions that reference it, ordered by offset ascending.
  slot_totals: Record<string, number>
  // Number of distinct slots touched, and a lower-bound estimate (in bytes) of
  // the local-variable region (magnitude of the most-negative offset).
  frame_slots: number
  locals_bytes: number
}

export interface MemorySummary {
  // Program-wide memory traffic: total memory reads (loads) and writes (stores)
  // across the whole program. Both keys are always present.
  memory_totals: Record<string, number>
}

export interface BranchSummary {
  // Program-wide branch flow counts. Per-line branch entries live on
  // LineMapping.branches; this summary tallies them.
  //   total          — number of branch instructions overall
  //   conditional    — count where mnemonic is not jmp/jmpl
  //   unconditional  — count of jmp/jmpl
  //   forward        — target's asm line > source's (if/else branch-around)
  //   backward       — target's asm line < source's (loop back-edge)
  //   self_loop      — target's asm line == source's
  //   external       — target label is not defined in this asm file (tail call)
  //   unknown        — indirect target (jmp *%eax) or missing operand
  total: number
  conditional: number
  unconditional: number
  forward: number
  backward: number
  self_loop: number
  external: number
  unknown: number
}

export interface GlossaryEntry {
  // One distinct x86 mnemonic present in the compiled asm, with a plain-English
  // meaning. `base` is the canonical opcode family; `category` matches the
  // instruction-mix buckets (mem / compute / branch / call / stack / other).
  mnemonic: string
  base: string
  category: string
  description: string
}

export interface CompileResponse {
  python_lines: string[]
  c_code: string
  c_lines: string[]
  asm_code: string
  asm_lines: string[]
  line_map: Record<number, LineMapping>
  // Present for the transpile pipeline; absent/null for pyghidra.
  cost_summary?: CostSummary | null
  // Present for the transpile pipeline; absent/null for pyghidra.
  register_summary?: RegisterSummary | null
  // Present for the transpile pipeline; absent/null for pyghidra.
  stack_summary?: StackSummary | null
  memory_summary?: MemorySummary | null
  // Present for the transpile pipeline; absent/null for pyghidra.
  branch_summary?: BranchSummary | null
  // Glossary of the distinct mnemonics in the compiled asm (transpile pipeline).
  asm_glossary?: GlossaryEntry[]
}

export type CompileMethod = 'transpile' | 'pyghidra'

export function compile(code: string, method: CompileMethod = 'transpile') {
  return request<CompileResponse>('/compile', {
    method: 'POST',
    body: JSON.stringify({ code, method }),
  })
}
