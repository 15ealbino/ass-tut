import { getApiBaseUrl } from './config'

/**
 * Thin fetch wrapper around the Assembly Tutorial backend.
 * Mirrors frontend/src/api.ts, but the base URL is resolved at call time
 * (it can be changed in-app) and the JWT is injected by the caller.
 */

let _token: string | null = null

export function setToken(t: string | null) {
  _token = t
}
export function hasToken() {
  return !!_token
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const base = await getApiBaseUrl()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (_token) headers['Authorization'] = `Bearer ${_token}`

  let res: Response
  try {
    res = await fetch(`${base}${path}`, { ...options, headers })
  } catch (e) {
    throw new Error(
      `Cannot reach the server at ${base}. Check your connection or the server URL. (${
        e instanceof Error ? e.message : 'network error'
      })`
    )
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(typeof err.detail === 'string' ? err.detail : 'Request failed')
  }
  return res.json() as Promise<T>
}

export interface AuthResponse {
  access_token: string
  token_type: string
}

export function register(email: string, password: string) {
  return request<AuthResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export function login(email: string, password: string) {
  return request<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export interface LineMapping {
  c_lines: number[]
  asm_lines: number[]
  color: string
}

export interface CompileResponse {
  python_lines: string[]
  c_code: string
  c_lines: string[]
  asm_code: string
  asm_lines: string[]
  line_map: Record<number, LineMapping>
}

export type CompileMethod = 'transpile' | 'pyghidra'

export function compile(code: string, method: CompileMethod = 'transpile') {
  return request<CompileResponse>('/compile', {
    method: 'POST',
    body: JSON.stringify({ code, method }),
  })
}

export function health() {
  return request<{ status: string }>('/health')
}
