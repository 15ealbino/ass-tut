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
  c_count?: number
  asm_count?: number
}

export interface LineMetric { c_count: number; asm_count: number }

export interface ExpansionMetrics {
  total_asm_instructions: number
  total_c_lines: number
  line_count: number
  mean_asm_per_line: number
  max_asm_line: number | null
  hotspots: number[]
  hotspot_threshold: number
  per_line: Record<number, LineMetric>
}

export interface CompileResponse {
  python_lines: string[]
  c_code: string
  c_lines: string[]
  asm_code: string
  asm_lines: string[]
  line_map: Record<number, LineMapping>
  metrics?: ExpansionMetrics | null
}

export type CompileMethod = 'transpile' | 'pyghidra'

export function compile(code: string, method: CompileMethod = 'transpile') {
  return request<CompileResponse>('/compile', {
    method: 'POST',
    body: JSON.stringify({ code, method }),
  })
}
