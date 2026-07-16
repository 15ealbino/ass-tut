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
}

export interface Hotspot { py_line: number; asm_count: number; flags: string[] }

export interface CostSummary { total_instructions: number; hotspots: Hotspot[] }

export interface CompileResponse {
  python_lines: string[]
  c_code: string
  c_lines: string[]
  asm_code: string
  asm_lines: string[]
  line_map: Record<number, LineMapping>
  // Present for the transpile pipeline; absent/null for pyghidra.
  cost_summary?: CostSummary | null
}

export type CompileMethod = 'transpile' | 'pyghidra'

export function compile(code: string, method: CompileMethod = 'transpile') {
  return request<CompileResponse>('/compile', {
    method: 'POST',
    body: JSON.stringify({ code, method }),
  })
}
