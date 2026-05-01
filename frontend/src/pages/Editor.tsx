import CodeMirror from '@uiw/react-codemirror'
import { python } from '@codemirror/lang-python'
import { oneDark } from '@codemirror/theme-one-dark'
import { useState } from 'react'
import { compile, CompileResponse, LineMapping } from '../api'
import CodePane from '../components/CodePane'
import AsmPane, { AsmLineInfo } from '../components/AsmPane'

// ─── Vulnerability catalogue ───────────────────────────────────────────────

interface Vuln {
  id: string
  name: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  category: string
  description: string
  explanation: string
  code: string
}

const VULNS: Vuln[] = [
  {
    id: 'stack-bof',
    name: 'STACK BUFFER OVERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Loop writes past a fixed-size buffer boundary.',
    explanation:
      'A stack buffer overflow occurs when a program writes beyond the end of a fixed-size buffer allocated on the stack. ' +
      'An attacker supplies input larger than the buffer to overwrite adjacent stack data — including the saved return address — ' +
      'redirecting execution to attacker-controlled shellcode. ' +
      'In the assembly, watch for `subq` allocating a small fixed frame (e.g. -32(%rbp)) while a loop counter ' +
      'driven by `addl`/`cmpl` iterates well past that boundary, overwriting the return address stored just above the frame.',
    code:
`# Stack buffer overflow: fixed buffer of 8, loop runs 16 iterations
def fill_buffer():
    buf_size = 8
    total_writes = 16
    value = 0
    i = 0
    while i < total_writes:
        value += i
        if i >= buf_size:
            print(value)
        i += 1
    return value

result = fill_buffer()
print(result)
`,
  },
  {
    id: 'int-overflow',
    name: 'INTEGER OVERFLOW',
    severity: 'HIGH',
    category: 'Arithmetic Error',
    description: 'Multiplication wraps past 32-bit signed maximum.',
    explanation:
      'Integer overflow happens when an arithmetic result exceeds the maximum value of its storage type, ' +
      'silently wrapping to a small or negative number. ' +
      'Attackers exploit this to cause under-allocated buffers: a size calculation overflows to a tiny value, ' +
      'then the program copies full-sized data into the under-allocated region. ' +
      'The assembly reveals this via `imull` operating on two large 32-bit operands — ' +
      'the CPU truncates the 64-bit product to 32 bits and stores the wrapped result with `movl`.',
    code:
`# Integer overflow: 50000 * 50000 exceeds 32-bit signed max (2147483647)
def calc_allocation():
    width = 50000
    height = 50000
    total = width * height
    max_int32 = 2147483647
    if total > max_int32:
        print(total)
    else:
        print(0)
    return total

size = calc_allocation()
print(size)
`,
  },
  {
    id: 'format-string',
    name: 'FORMAT STRING',
    severity: 'HIGH',
    category: 'Injection',
    description: 'User input embedded in format output without sanitization.',
    explanation:
      'A format string vulnerability occurs when attacker-controlled data is passed directly as a format specifier ' +
      'rather than as a plain argument, letting the attacker read stack memory or write arbitrary values. ' +
      'Classically exploited via printf(user_input) instead of printf("%s", user_input). ' +
      'In the assembly, the unsanitized value is loaded into %rdi (the first argument register) via `movq` ' +
      'and passed directly to the `call` for the output function — no sanitization instructions appear between load and call.',
    code:
`# Format string: raw user-controlled value used as output argument
def log_message():
    user_input = 1094861636
    prefix = 0
    combined = prefix + user_input
    print(combined)
    return combined

def process():
    code = log_message()
    if code > 0:
        print(code)
    return code

process()
`,
  },
  {
    id: 'use-after-free',
    name: 'USE-AFTER-FREE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Memory accessed after it has been freed/zeroed.',
    explanation:
      'Use-after-free occurs when a program dereferences a pointer after the memory it points to has been freed. ' +
      'Attackers reclaim the freed memory with controlled data and wait for the dangling pointer to be used, ' +
      'achieving arbitrary code execution or data corruption. ' +
      'The assembly shows the pointer value loaded from the stack into a register, a zeroing sequence (simulating free), ' +
      'and then a subsequent `movl`/`movq` that dereferences the same register address — ' +
      'at runtime the memory region now contains attacker data.',
    code:
`# Use-after-free: ptr is zeroed (freed) then dereferenced again
def process_object():
    ptr = 255
    data = ptr * 2
    ptr = 0
    if data > 0:
        result = data + ptr
        print(result)
    return data

val = process_object()
print(val)
`,
  },
  {
    id: 'null-deref',
    name: 'NULL POINTER DEREF',
    severity: 'HIGH',
    category: 'Memory Error',
    description: 'Dereference of unvalidated null/zero pointer causes crash.',
    explanation:
      'A null pointer dereference occurs when code reads or writes through a pointer that holds address zero, ' +
      'crashing the process or — on systems without null-page protection — executing attacker-mapped shellcode at address 0. ' +
      'Attackers exploit missing null checks after allocation failures or error returns. ' +
      'In the assembly, `testl %eax, %eax` or `cmpq $0` checks are absent before the pointer is used in a `movq (%rax)` ' +
      'dereference — the CPU accesses address 0 and raises a segmentation fault.',
    code:
`# Null pointer: ptr is zero; dereferencing crashes at address 0
def read_config():
    ptr = 0
    default = 99
    if ptr > 0:
        result = ptr * default
    else:
        result = ptr + default
    print(result)
    return result

cfg = read_config()
print(cfg)
`,
  },
  {
    id: 'cmd-injection',
    name: 'COMMAND INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'Unsanitized user input concatenated into a shell command.',
    explanation:
      'Command injection lets an attacker embed shell metacharacters (;, &&, |, $()) in user-supplied input ' +
      'that is passed to a shell interpreter, executing arbitrary commands with the application\'s privileges. ' +
      'Even a numeric input field is dangerous if not strictly validated before concatenation. ' +
      'The assembly reveals this pattern via a sequence of `leaq` (load string address) and `addq`/`movq` operations ' +
      'that concatenate user data into a buffer which is then passed to `call system` — ' +
      'no character-filtering instructions appear in between.',
    code:
`# Command injection: user_input concatenated into command string unsanitized
def build_command():
    base = 1000
    user_input = 42
    command = base + user_input
    print(command)
    return command

def execute():
    cmd = build_command()
    if cmd > 0:
        result = cmd * 2
        print(result)
    return cmd

execute()
`,
  },
  {
    id: 'int-truncation',
    name: 'INTEGER TRUNCATION',
    severity: 'MEDIUM',
    category: 'Arithmetic Error',
    description: 'Large value silently truncated when stored in smaller type.',
    explanation:
      'Integer truncation occurs when a value computed in a wider type (e.g. 32-bit) is stored in a narrower one (e.g. 8-bit), ' +
      'silently discarding the high bits. ' +
      'Attackers use this to bypass length checks: a size of 256 truncates to 0 in a byte, ' +
      'causing a zero-length allocation followed by a full-size copy. ' +
      'In the assembly the result of `imull` or `addl` (32-bit) is stored via `movb` (byte store), ' +
      'and the compiler emits no overflow check between the wide computation and the narrow store.',
    code:
`# Integer truncation: 300 cannot fit in a byte (max 255), high bits lost
def store_byte():
    large_val = 300
    byte_max = 255
    truncated = large_val - byte_max - 1
    stored = truncated
    if stored > 0:
        print(stored)
    else:
        print(0)
    return stored

result = store_byte()
print(result)
`,
  },
  {
    id: 'uninit-var',
    name: 'UNINITIALIZED VAR',
    severity: 'MEDIUM',
    category: 'Memory Error',
    description: 'Variable read before guaranteed assignment on all paths.',
    explanation:
      'Reading an uninitialized variable exposes whatever bytes happened to be on the stack from a previous call frame — ' +
      'potentially leaking sensitive data like passwords, keys, or addresses that defeat ASLR. ' +
      'Attackers craft call sequences that place useful values in the stack slot before triggering the uninitialized read. ' +
      'In the assembly, `result` is allocated on the stack via `subq` but no `movl` initialization appears before the ' +
      'conditional branch that may skip assignment — the `movl` that reads it at the return can fetch stale stack data.',
    code:
`# Uninitialized variable: result is only set on one branch
def compute():
    flag = 0
    result = 0
    if flag > 0:
        result = 42
    elif flag < 0:
        result = -1
    print(result)
    return result

def run():
    x = compute()
    if x > 0:
        print(x)
    return x

run()
`,
  },
]

// ─── Severity helpers ──────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'var(--red)',
  HIGH: '#ff8c00',
  MEDIUM: 'var(--cyan)',
}

const STARTER = `# Write Python below and click [> COMPILE]
x = 10
y = 20

for i in range(5):
    x += i

if x > 30:
    print(x)
else:
    print(y)
`

// ─── EditorPage ────────────────────────────────────────────────────────────

export default function EditorPage() {
  const [code, setCode] = useState(STARTER)
  const [result, setResult] = useState<CompileResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [activePyLine, setActivePyLine] = useState<number | null>(null)
  const [activeVuln, setActiveVuln] = useState<Vuln | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  async function handleCompile() {
    setLoading(true)
    setError('')
    setActivePyLine(null)
    try {
      const res = await compile(code)
      setResult(res)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Compilation failed')
    } finally {
      setLoading(false)
    }
  }

  function handleCodeChange(val: string) {
    setCode(val)
    // Clear vuln advisory when user manually edits
    if (activeVuln) setActiveVuln(null)
  }

  function selectVuln(v: Vuln) {
    setCode(v.code)
    setActiveVuln(v)
    setResult(null)
    setError('')
    setActivePyLine(null)
  }

  // Build color highlight maps
  const pyHighlight: Record<number, string> = {}
  const cHighlight: Record<number, string> = {}
  const asmHighlight: Record<number, string> = {}
  const asmToInfo: Record<number, AsmLineInfo> = {}

  if (result) {
    for (const [pyLineStr, mapping] of Object.entries(result.line_map)) {
      const m = mapping as LineMapping
      const pyLine = Number(pyLineStr)
      const pyCode = result.python_lines[pyLine - 1] ?? ''
      pyHighlight[pyLine] = m.color
      for (const cl of m.c_lines) cHighlight[cl] = m.color
      for (const al of m.asm_lines) {
        asmHighlight[al] = m.color
        asmToInfo[al] = { pyLine, pyCode, color: m.color }
      }
    }
  }

  const activeCLines = new Set<number>()
  const activeAsmLines = new Set<number>()

  if (activePyLine && result) {
    const m = result.line_map[activePyLine] as LineMapping | undefined
    if (m) {
      m.c_lines.forEach(l => activeCLines.add(l))
      m.asm_lines.forEach(l => activeAsmLines.add(l))
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg-base)' }}>

      {/* ── Header ── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        padding: '8px 20px',
        background: 'var(--bg-header)',
        borderBottom: '1px solid var(--border-mid)',
        gap: 16,
        flexShrink: 0,
      }}>
        <span style={{ fontWeight: 700, fontSize: 16, letterSpacing: '0.12em', fontFamily: 'Fira Code, monospace' }}>
          <span style={{ color: 'var(--green)' }}>CYBER</span>
          <span style={{ color: 'var(--text-dim)' }}>//</span>
          <span style={{ color: 'var(--cyan)' }}>ASM</span>
          <span className="cursor-blink" style={{ color: 'var(--green)', marginLeft: 2 }}>_</span>
        </span>

        <span style={{ color: 'var(--border-bright)', fontSize: 10 }}>|</span>

        <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'Fira Code, monospace', letterSpacing: '0.04em' }}>
          SELECT PYTHON LINE → TRACE C → ASM
        </span>

        <span style={{ flex: 1 }} />

        {loading && (
          <span style={{ fontSize: 11, color: 'var(--cyan)', letterSpacing: '0.08em' }}>◈ COMPILING...</span>
        )}
        {result && !loading && (
          <span style={{ fontSize: 11, color: 'var(--green)', letterSpacing: '0.08em' }}>◉ COMPILED OK</span>
        )}

        <button
          onClick={handleCompile}
          disabled={loading}
          style={{
            background: loading ? 'transparent' : 'var(--green-faint)',
            color: loading ? 'var(--text-dim)' : 'var(--green)',
            border: `1px solid ${loading ? 'var(--border-dim)' : 'var(--green)'}`,
            padding: '6px 18px',
            fontSize: 12,
            letterSpacing: '0.1em',
            boxShadow: loading ? 'none' : 'var(--glow-green)',
          }}
        >
          {loading ? '[ COMPILING… ]' : '[> COMPILE ]'}
        </button>
      </div>

      {/* ── Error bar ── */}
      {error && (
        <div style={{
          background: '#1a0008',
          color: 'var(--red)',
          padding: '6px 20px',
          fontSize: 12,
          fontFamily: 'Fira Code, monospace',
          borderBottom: '1px solid var(--red)',
          boxShadow: 'var(--glow-red)',
          letterSpacing: '0.04em',
          flexShrink: 0,
        }}>
          [!] ERR :: {error}
        </div>
      )}

      {/* ── Body: sidebar + panes ── */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

        {/* ── Vuln sidebar ── */}
        <div style={{
          width: sidebarOpen ? 262 : 28,
          flexShrink: 0,
          display: 'flex',
          flexDirection: 'column',
          background: 'var(--bg-header)',
          borderRight: '1px solid var(--border-mid)',
          transition: 'width 0.18s ease',
          overflow: 'hidden',
          position: 'relative',
        }}>
          {/* Sidebar header row */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            padding: '7px 8px',
            borderBottom: '1px solid var(--border-dim)',
            gap: 6,
            flexShrink: 0,
          }}>
            {sidebarOpen && (
              <span style={{
                fontWeight: 700,
                fontSize: 11,
                color: 'var(--red)',
                letterSpacing: '0.14em',
                fontFamily: 'Fira Code, monospace',
                whiteSpace: 'nowrap',
                flex: 1,
              }}>
                &gt;_ VULN//LAB
              </span>
            )}
            <button
              onClick={() => setSidebarOpen(o => !o)}
              title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
              style={{
                padding: '2px 6px',
                fontSize: 11,
                color: 'var(--text-dim)',
                border: '1px solid var(--border-dim)',
                flexShrink: 0,
              }}
            >
              {sidebarOpen ? '◀' : '▶'}
            </button>
          </div>

          {/* Vuln card list */}
          {sidebarOpen && (
            <div style={{ overflowY: 'auto', flex: 1, padding: '6px 6px' }}>
              {VULNS.map(v => {
                const isActive = activeVuln?.id === v.id
                const sevColor = SEVERITY_COLOR[v.severity]
                return (
                  <button
                    key={v.id}
                    onClick={() => selectVuln(v)}
                    title={v.description}
                    style={{
                      display: 'block',
                      width: '100%',
                      textAlign: 'left',
                      background: isActive ? `${sevColor}14` : 'transparent',
                      border: `1px solid ${isActive ? sevColor : 'var(--border-dim)'}`,
                      borderRadius: 2,
                      padding: '7px 8px',
                      marginBottom: 5,
                      cursor: 'pointer',
                      boxShadow: isActive ? `0 0 8px ${sevColor}33` : 'none',
                      transition: 'all 0.12s',
                    }}
                  >
                    {/* Vuln name + severity badge */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
                      <span style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: isActive ? sevColor : 'var(--text-primary)',
                        fontFamily: 'Fira Code, monospace',
                        letterSpacing: '0.06em',
                        flex: 1,
                        lineHeight: 1.2,
                      }}>
                        {v.name}
                      </span>
                      <span style={{
                        fontSize: 8,
                        fontWeight: 700,
                        color: sevColor,
                        border: `1px solid ${sevColor}`,
                        borderRadius: 2,
                        padding: '1px 4px',
                        fontFamily: 'Fira Code, monospace',
                        letterSpacing: '0.06em',
                        flexShrink: 0,
                      }}>
                        {v.severity}
                      </span>
                    </div>
                    {/* Category + description */}
                    <div style={{
                      fontSize: 9,
                      color: 'var(--text-dim)',
                      fontFamily: 'Fira Code, monospace',
                      letterSpacing: '0.04em',
                      marginBottom: 2,
                    }}>
                      [{v.category}]
                    </div>
                    <div style={{
                      fontSize: 9,
                      color: isActive ? 'var(--text-dim)' : 'var(--text-muted)',
                      fontFamily: 'Fira Code, monospace',
                      lineHeight: 1.4,
                      whiteSpace: 'normal',
                    }}>
                      {v.description}
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </div>

        {/* ── Three-pane workspace ── */}
        <div style={{ display: 'flex', flex: 1, overflow: 'hidden', gap: 6, padding: 6 }}>

          {/* Python editor */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            flex: 1,
            minWidth: 0,
            background: 'var(--bg-panel)',
            borderRadius: 2,
            overflow: 'hidden',
            border: activeVuln
              ? `1px solid ${SEVERITY_COLOR[activeVuln.severity]}55`
              : '1px solid var(--border-dim)',
            boxShadow: activeVuln
              ? `0 0 12px ${SEVERITY_COLOR[activeVuln.severity]}22`
              : 'none',
          }}>
            <PaneHeader
              title="PYTHON"
              badge={activeVuln ? activeVuln.name : 'INPUT'}
              badgeColor={activeVuln ? SEVERITY_COLOR[activeVuln.severity] : 'var(--green)'}
            />
            <div style={{ flex: 1, overflow: 'auto' }}>
              <CodeMirror
                value={code}
                onChange={handleCodeChange}
                extensions={[python()]}
                theme={oneDark}
                style={{ height: '100%', fontSize: 13 }}
                basicSetup={{ lineNumbers: true, foldGutter: false }}
              />
            </div>
          </div>

          {/* C output */}
          {result ? (
            <CodePane
              title="C"
              badge="TRANSPILED"
              lines={result.c_lines}
              highlightMap={cHighlight}
              activeLines={activeCLines}
            />
          ) : (
            <PlaceholderPane title="C" badge="TRANSPILED" />
          )}

          {/* Assembly output */}
          {result ? (
            <AsmPane
              title="x86 ASM"
              badge="GCC -O0"
              lines={result.asm_lines}
              highlightMap={asmHighlight}
              activeLines={activeAsmLines}
              infoMap={asmToInfo}
              vuln={activeVuln ? {
                name: activeVuln.name,
                severity: activeVuln.severity,
                explanation: activeVuln.explanation,
              } : null}
            />
          ) : (
            <PlaceholderPane title="x86 ASM" badge="GCC -O0" />
          )}
        </div>
      </div>

      {/* ── Legend / status bar ── */}
      {result && (
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 4,
          padding: '5px 10px',
          background: 'var(--bg-header)',
          borderTop: '1px solid var(--border-mid)',
          minHeight: 34,
          flexShrink: 0,
        }}>
          <span style={{
            fontSize: 9,
            color: 'var(--text-dim)',
            letterSpacing: '0.12em',
            marginRight: 6,
            whiteSpace: 'nowrap',
          }}>
            TRACE::
          </span>
          {result.python_lines.map((line, i) => {
            const pyLine = i + 1
            const mapping = result.line_map[pyLine] as LineMapping | undefined
            if (!mapping) return null
            const isActive = activePyLine === pyLine
            return (
              <button
                key={pyLine}
                onClick={() => setActivePyLine(isActive ? null : pyLine)}
                style={{
                  background: isActive ? `${mapping.color}22` : 'transparent',
                  color: isActive ? mapping.color : `${mapping.color}99`,
                  border: `1px solid ${isActive ? mapping.color : `${mapping.color}44`}`,
                  borderRadius: 2,
                  padding: '1px 8px',
                  fontSize: 10,
                  fontFamily: 'Fira Code, monospace',
                  maxWidth: 180,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  letterSpacing: '0.04em',
                  boxShadow: isActive ? `0 0 6px ${mapping.color}55` : 'none',
                  transition: 'all 0.1s',
                }}
                title={`Line ${pyLine}: ${line}`}
              >
                L{pyLine}: {line.trim().slice(0, 24)}{line.trim().length > 24 ? '…' : ''}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Shared sub-components ─────────────────────────────────────────────────

function PaneHeader({ title, badge, badgeColor }: { title: string; badge?: string; badgeColor?: string }) {
  return (
    <div style={{
      padding: '7px 14px',
      background: 'var(--bg-header)',
      borderBottom: '1px solid var(--border-dim)',
      display: 'flex',
      alignItems: 'center',
      gap: 8,
    }}>
      <span style={{
        fontWeight: 700,
        fontSize: 11,
        color: 'var(--text-dim)',
        textTransform: 'uppercase',
        letterSpacing: '0.14em',
        fontFamily: 'Fira Code, monospace',
      }}>
        &gt;_ {title}
      </span>
      {badge && (
        <span style={{
          background: `${badgeColor ?? 'var(--cyan)'}18`,
          color: badgeColor ?? 'var(--cyan)',
          border: `1px solid ${badgeColor ?? 'var(--cyan)'}44`,
          borderRadius: 2,
          padding: '0 6px',
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: '0.1em',
          fontFamily: 'Fira Code, monospace',
        }}>
          {badge}
        </span>
      )}
    </div>
  )
}

function PlaceholderPane({ title, badge }: { title: string; badge?: string }) {
  return (
    <div style={{
      flex: 1,
      minWidth: 0,
      background: 'var(--bg-panel)',
      borderRadius: 2,
      border: '1px solid var(--border-dim)',
      display: 'flex',
      flexDirection: 'column',
    }}>
      <PaneHeader title={title} badge={badge} />
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        color: 'var(--text-muted)',
        fontFamily: 'Fira Code, monospace',
        fontSize: 12,
      }}>
        <pre style={{ color: 'var(--border-bright)', lineHeight: '1.4', fontSize: 11, margin: 0 }}>{
`┌─────────────────┐
│  AWAITING INPUT │
└─────────────────┘`
        }</pre>
        <span style={{ fontSize: 10, letterSpacing: '0.1em', color: 'var(--text-dim)' }}>
          PRESS <span style={{ color: 'var(--green)' }}>[&gt; COMPILE]</span> TO BEGIN
        </span>
        <span className="cursor-blink" style={{ color: 'var(--green)', fontSize: 16 }}>█</span>
      </div>
    </div>
  )
}
