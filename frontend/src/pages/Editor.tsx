import CodeMirror from '@uiw/react-codemirror'
import { python } from '@codemirror/lang-python'
import { oneDark } from '@codemirror/theme-one-dark'
import { useState, useRef } from 'react'
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
    description: 'Loop smashes past a fixed stack frame, clobbering the return address.',
    explanation:
      'Classic stack smashing: a fixed-size buffer lives on the stack, but the loop bound comes from ' +
      'attacker-controlled input. Once the write index exceeds the buffer, subsequent iterations overwrite ' +
      'adjacent stack slots — first local variables, then the saved frame pointer, then the return address. ' +
      'The attacker points the return address at shellcode or a ROP gadget. ' +
      'In the assembly, `subq $N, %rsp` allocates a small fixed frame while the loop\'s `cmpl` compares ' +
      'against a much larger bound; the `movl` inside the loop reaches past %rbp once the index exceeds N/4.',
    code:
`# CVE pattern: fixed stack buf[8], loop bound 64 — smashes return addr
def copy_input():
    buf_size = 8
    input_len = 64
    total = 0
    i = 0
    while i < input_len:
        total += i
        if i >= buf_size:
            total += 1
        i += 1
    return total

result = copy_input()
print(result)
`,
  },
  {
    id: 'heap-uaf',
    name: 'HEAP USE-AFTER-FREE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Object fields accessed after the object is freed and its memory reclaimed.',
    explanation:
      'Use-after-free is behind a huge share of browser CVEs (Chrome, Firefox, Safari). ' +
      'The allocator is free to hand the released chunk to a different allocation; ' +
      'if an attacker triggers a heap spray first, they control what bytes now occupy the old slot. ' +
      'The object\'s method dispatch reads a function pointer from the now-attacker-controlled memory, ' +
      'redirecting execution. ' +
      'In the assembly, the struct is zeroed (ptr = 0, size = 0 simulates free), yet the subsequent ' +
      '`movl` still reads from the same stack offset — at runtime that region holds attacker data.',
    code:
`# CVE pattern: object freed (zeroed), dangling field access follows
class Chunk:
    def __init__(self, size):
        self.size = size
        self.data = size * 4
        self.freed = 0

    def read(self):
        result = self.data + self.size
        return result

c = Chunk(64)
c.freed = 1
c.size = 0
c.data = 0
stale = c.read()
print(stale)
`,
  },
  {
    id: 'vtable-hijack',
    name: 'VTABLE HIJACK',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Attacker overwrites a function-pointer field to redirect virtual dispatch.',
    explanation:
      'C++ vtable hijacking is a cornerstone exploit technique. Every polymorphic object holds a pointer ' +
      'to its vtable — a table of function pointers for virtual methods. ' +
      'When a use-after-free or heap overflow lets an attacker write to the object\'s memory layout, ' +
      'they overwrite the vtable pointer (or a specific slot) with an address they control. ' +
      'The next virtual call becomes an indirect jump to attacker-chosen code. ' +
      'In the assembly, `movl` writes 0x41414141 (AAAA) into the handler field, then `imull`/`movl` ' +
      'uses that value directly — an attacker replaces it with a gadget or shellcode address.',
    code:
`# CVE pattern: vtable-style handler pointer overwritten by attacker
class VTable:
    def __init__(self, handler):
        self.handler = handler
        self.refcount = 1
        self.flags = 0

    def dispatch(self):
        result = self.handler * 2
        self.flags += 1
        return result

vt = VTable(4196352)
vt.handler = 1094795585
result = vt.dispatch()
print(result)
`,
  },
  {
    id: 'double-free',
    name: 'DOUBLE FREE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Same memory block freed twice, corrupting allocator metadata.',
    explanation:
      'Double-free corrupts the heap allocator\'s free-list metadata. ' +
      'Modern allocators (ptmalloc, jemalloc) use inline linked-list pointers in freed chunks. ' +
      'Freeing the same chunk twice lets an attacker — who controls a subsequent allocation — ' +
      'overwrite those pointers, turning the next malloc into an arbitrary-write primitive. ' +
      'Exploited in CVE-2019-11477 (Linux TCP SACK), CVE-2022-0185, and many others. ' +
      'The assembly shows free_count incremented twice from the same base address; ' +
      'a real allocator would detect this via its tcache key check and abort, ' +
      'but older versions silently corrupt the bin.',
    code:
`# CVE pattern: free() called twice on the same block
class MemBlock:
    def __init__(self, size):
        self.size = size
        self.ptr = size * 8
        self.free_count = 0

    def free(self):
        self.ptr = 0
        self.free_count += 1

block = MemBlock(32)
block.free()
block.free()
result = block.free_count
print(result)
`,
  },
  {
    id: 'off-by-one',
    name: 'OFF-BY-ONE OVERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: '<= instead of < lets the loop write one slot past the buffer end.',
    explanation:
      'Off-by-one overflows are deceptively simple: a single misplaced `<=` makes the loop run one ' +
      'iteration too many, writing exactly one element past the buffer boundary. ' +
      'On the stack this overwrites the low byte of the saved frame pointer (%rbp), ' +
      'which the compiler uses to restore the caller\'s stack frame on return — ' +
      'giving the attacker control of where the caller resumes execution. ' +
      'Exploited in CVE-2021-3156 (sudo heap off-by-one), OpenSSH, and Sendmail. ' +
      'In the assembly, the `cmpl` bound is buf_size (8) but the loop condition uses `<=` so it ' +
      'executes with i=8, writing a 9th element one slot past the 8-element frame.',
    code:
`# CVE pattern: <= instead of < writes one element past the buffer
def copy_buf():
    buf_size = 8
    i = 0
    total = 0
    while i <= buf_size:
        total += i
        if i == buf_size:
            total += 9999
        i += 1
    return total

result = copy_buf()
print(result)
`,
  },
  {
    id: 'cmd-injection',
    name: 'COMMAND INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'Unsanitized user-controlled value piped into a shell command.',
    explanation:
      'Command injection lets an attacker embed shell metacharacters — ; && | $() — in any field ' +
      'that reaches a shell interpreter. Even a numeric parameter is dangerous if passed through ' +
      'string concatenation: "ping -c 1 " + user_ip becomes "ping -c 1 127.0.0.1; cat /etc/passwd" ' +
      'when the attacker supplies "127.0.0.1; cat /etc/passwd". ' +
      'The assembly shows the user-supplied value loaded via `movl` then added directly into a buffer ' +
      'passed to the output call — no range check or character-filter instructions appear between ' +
      'the load and the `call`. In a real system this buffer feeds system() or execve().',
    code:
`# CVE pattern: user value reaches exec pipeline without validation
class ShellRunner:
    def __init__(self, base_cmd):
        self.base_cmd = base_cmd
        self.user_input = 0
        self.executed = 0

    def set_input(self, val):
        self.user_input = val

    def run(self):
        payload = self.base_cmd + self.user_input
        self.executed += 1
        return payload

runner = ShellRunner(1000)
runner.set_input(1094861636)
result = runner.run()
print(result)
`,
  },
  {
    id: 'type-confusion',
    name: 'TYPE CONFUSION',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Object reinterpreted as a different type; fields map to attacker-controlled offsets.',
    explanation:
      'Type confusion vulnerabilities treat memory allocated as one type as if it were a different type. ' +
      'In C++ this commonly happens via incorrect downcasts, union misuse, or corrupted vtable pointers. ' +
      'The attacker arranges for an object of type A to be cast to type B; field offsets differ, ' +
      'so reading "field 0 of B" actually reads an unrelated value from A\'s layout. ' +
      'Exploited extensively in V8 (Chrome JS engine): JIT-compiled code assumes an object\'s type tag ' +
      'is stable, but a side-channel trick changes the tag between the check and the use. ' +
      'In the assembly, two structs share a stack frame; the second struct\'s field reads overlap ' +
      'the first struct\'s data — the `movl` at offset -8(%rbp) reads what was written as a size, ' +
      'not a handler.',
    code:
`# CVE pattern: two structs share memory; field offsets alias
class TypeA:
    def __init__(self, size, data):
        self.size = size
        self.data = data
        self.checksum = size + data

class TypeB:
    def __init__(self, handler, flags):
        self.handler = handler
        self.flags = flags
        self.refcount = 1

a = TypeA(256, 1094795585)
b = TypeB(a.data, a.size)
confused = b.handler + b.flags
print(confused)
`,
  },
  {
    id: 'rop-gadget',
    name: 'ROP CHAIN SETUP',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Stack smash loads attacker addresses into saved registers for a ROP chain.',
    explanation:
      'Return-Oriented Programming (ROP) is the primary code-execution technique on systems with ' +
      'non-executable stack (NX/DEP). Instead of injecting shellcode, the attacker overwrites the ' +
      'stack with a chain of return addresses — each pointing to a short "gadget" (existing code ' +
      'ending in `ret`) that performs one small operation. Chaining gadgets achieves arbitrary computation. ' +
      'The setup stage: a stack overflow writes attacker-chosen values into saved register slots. ' +
      'In the assembly, `movl` stores 0xdeadbeef and 0x400600 into stack slots that the epilogue\'s ' +
      '`popq` will restore into %rbx and %r12 — those registers become the first two gadget addresses ' +
      'once the function returns.',
    code:
`# ROP setup: overflow writes gadget addresses into callee-saved slots
def build_rop_frame():
    saved_rbx = 3735928559
    saved_r12 = 4195840
    saved_r13 = 4196096
    chain_len = 0
    i = 0
    while i < 8:
        if i == 0:
            chain_len = saved_rbx
        elif i == 1:
            chain_len += saved_r12
        elif i == 2:
            chain_len += saved_r13
        i += 1
    return chain_len

payload = build_rop_frame()
print(payload)
`,
  },
  {
    id: 'toctou-race',
    name: 'TOCTOU RACE CONDITION',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Resource state changes between security check and use, bypassing access control.',
    explanation:
      'Time-of-Check Time-of-Use (TOCTOU / CWE-367) is a race condition where the program checks a ' +
      'condition (e.g. file permissions, ownership, credential validity) and then acts on the result, ' +
      'but an attacker modifies the resource in the window between the check and the use. ' +
      'The classic UNIX exploit: a setuid program calls access() to verify a user may read a file, ' +
      'then calls open() — the attacker uses a symlink swap between the two calls to redirect ' +
      'the open to /etc/shadow. Exploited in CVE-2024-7348 (PostgreSQL pg_dump — attacker replaces ' +
      'a relation with a view during the race window to execute arbitrary SQL as a superuser), ' +
      'CVE-2024-50379 (Apache Tomcat — TOCTOU during JSP compilation enables RCE on case-insensitive ' +
      'file systems), and a Docker TOCTOU (CVE-2019-19921) that granted root access to the host filesystem. ' +
      'At Pwn2Own 2023 a TOCTOU bug was used to compromise a Tesla Model 3. ' +
      'In the assembly, the `cmpl` from the check and the `movl` from the use reference the same ' +
      'stack offset, but no lock or atomic operation guards the gap — a concurrent write between ' +
      'the two instructions changes the value the use reads.',
    code:
`# CVE pattern: check-then-use gap lets attacker swap resource
class Resource:
    def __init__(self, owner, perms):
        self.owner = owner
        self.perms = perms
        self.data = 0
        self.modified = 0

    def set_data(self, val):
        self.data = val
        self.modified = 1

class AccessChecker:
    def __init__(self, required_perms):
        self.required_perms = required_perms
        self.check_passed = 0
        self.used = 0

    def check(self, res):
        if res.perms >= self.required_perms:
            self.check_passed = 1
        return self.check_passed

    def use(self, res):
        result = res.data * self.check_passed
        self.used = 1
        return result

res = Resource(1000, 755)
checker = AccessChecker(644)
checker.check(res)
res.data = 3735928559
res.owner = 0
privileged_read = checker.use(res)
print(privileged_read)
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
  const [paneOrder, setPaneOrder] = useState<Array<'python' | 'c' | 'asm'>>(['python', 'c', 'asm'])
  const [closedPanes, setClosedPanes] = useState(new Set<string>())
  const [dragOver, setDragOver] = useState<string | null>(null)
  const dragSrc = useRef<string | null>(null)

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

  function closePane(pane: string) { setClosedPanes(prev => new Set([...prev, pane])) }
  function openPane(pane: string) { setClosedPanes(prev => { const n = new Set(prev); n.delete(pane); return n }) }

  function movePane(pane: string, direction: -1 | 1) {
    setPaneOrder(prev => {
      const o = [...prev] as Array<'python' | 'c' | 'asm'>
      const idx = o.indexOf(pane as 'python' | 'c' | 'asm')
      // Skip past any closed panes to find the nearest visible neighbour
      let swapIdx = idx + direction
      while (swapIdx >= 0 && swapIdx < o.length) {
        if (!closedPanes.has(o[swapIdx])) {
          ;[o[idx], o[swapIdx]] = [o[swapIdx], o[idx]]
          return o
        }
        swapIdx += direction
      }
      return o
    })
  }

  function handlePaneDragStart(pane: string, e: React.DragEvent) {
    dragSrc.current = pane
    e.dataTransfer.effectAllowed = 'move'
  }
  function handlePaneDragOver(pane: string, e: React.DragEvent) {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    if (dragSrc.current !== pane) setDragOver(pane)
  }
  function handlePaneDrop(pane: string, e: React.DragEvent) {
    e.preventDefault()
    if (dragSrc.current && dragSrc.current !== pane) {
      setPaneOrder(prev => {
        const o = [...prev] as Array<'python' | 'c' | 'asm'>
        const si = o.indexOf(dragSrc.current as 'python' | 'c' | 'asm')
        const ti = o.indexOf(pane as 'python' | 'c' | 'asm')
        ;[o[si], o[ti]] = [o[ti], o[si]]
        return o
      })
    }
    dragSrc.current = null
    setDragOver(null)
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
        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden', padding: 6, gap: 0 }}>

          {/* Restore bar — shown when panes are closed */}
          {closedPanes.size > 0 && (
            <div style={{ display: 'flex', gap: 4, marginBottom: 6, flexShrink: 0, flexWrap: 'wrap' }}>
              {paneOrder.filter(p => closedPanes.has(p)).map(p => {
                const label: Record<string, string> = { python: 'PYTHON', c: 'C', asm: 'x86 ASM' }
                return (
                  <button
                    key={p}
                    onClick={() => openPane(p)}
                    style={{
                      fontSize: 10,
                      color: 'var(--cyan)',
                      border: '1px solid var(--cyan)44',
                      background: '#00ccff0d',
                      borderRadius: 2,
                      padding: '3px 10px',
                      letterSpacing: '0.1em',
                      fontFamily: 'Fira Code, monospace',
                      boxShadow: '0 0 4px #00ccff22',
                    }}
                  >
                    [+] {label[p] ?? p.toUpperCase()}
                  </button>
                )
              })}
            </div>
          )}

          {/* Panes row */}
          <div style={{ display: 'flex', flex: 1, overflow: 'hidden', gap: 6 }}>
            {(() => {
              const visible = paneOrder.filter(p => !closedPanes.has(p))
              return visible.map((pane, idx) => {
                const canLeft  = idx > 0
                const canRight = idx < visible.length - 1
                return (
                <div
                  key={pane}
                  onDragOver={e => handlePaneDragOver(pane, e)}
                  onDrop={e => handlePaneDrop(pane, e)}
                  onDragLeave={e => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragOver(null) }}
                  onDragEnd={() => { dragSrc.current = null; setDragOver(null) }}
                  style={{
                    flex: 1,
                    minWidth: 0,
                    display: 'flex',
                    flexDirection: 'column',
                    borderRadius: 2,
                    outline: dragOver === pane ? '2px dashed #00ccff88' : '2px dashed transparent',
                    transition: 'outline-color 0.12s',
                  }}
                >
                  {/* Python editor */}
                  {pane === 'python' && (
                    <div style={{
                      display: 'flex',
                      flexDirection: 'column',
                      flex: 1,
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
                        onClose={() => closePane('python')}
                        onDragStart={e => handlePaneDragStart('python', e)}
                        onMoveLeft={canLeft ? () => movePane('python', -1) : undefined}
                        onMoveRight={canRight ? () => movePane('python', 1) : undefined}
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
                  )}

                  {/* C output */}
                  {pane === 'c' && (result ? (
                    <CodePane
                      title="C"
                      badge="TRANSPILED"
                      lines={result.c_lines}
                      highlightMap={cHighlight}
                      activeLines={activeCLines}
                      onClose={() => closePane('c')}
                      onDragStart={e => handlePaneDragStart('c', e)}
                      onMoveLeft={canLeft ? () => movePane('c', -1) : undefined}
                      onMoveRight={canRight ? () => movePane('c', 1) : undefined}
                    />
                  ) : (
                    <PlaceholderPane
                      title="C"
                      badge="TRANSPILED"
                      onClose={() => closePane('c')}
                      onDragStart={e => handlePaneDragStart('c', e)}
                      onMoveLeft={canLeft ? () => movePane('c', -1) : undefined}
                      onMoveRight={canRight ? () => movePane('c', 1) : undefined}
                    />
                  ))}

                  {/* Assembly output */}
                  {pane === 'asm' && (result ? (
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
                      onClose={() => closePane('asm')}
                      onDragStart={e => handlePaneDragStart('asm', e)}
                      onMoveLeft={canLeft ? () => movePane('asm', -1) : undefined}
                      onMoveRight={canRight ? () => movePane('asm', 1) : undefined}
                    />
                  ) : (
                    <PlaceholderPane
                      title="x86 ASM"
                      badge="GCC -O0"
                      onClose={() => closePane('asm')}
                      onDragStart={e => handlePaneDragStart('asm', e)}
                      onMoveLeft={canLeft ? () => movePane('asm', -1) : undefined}
                      onMoveRight={canRight ? () => movePane('asm', 1) : undefined}
                    />
                  ))}
                </div>
              )})
            })()}
          </div>
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

function PaneHeader({
  title, badge, badgeColor, onClose, onDragStart, onMoveLeft, onMoveRight,
}: {
  title: string; badge?: string; badgeColor?: string;
  onClose?: () => void; onDragStart?: (e: React.DragEvent) => void;
  onMoveLeft?: () => void; onMoveRight?: () => void;
}) {
  return (
    <div style={{
      padding: '7px 10px',
      background: 'var(--bg-header)',
      borderBottom: '1px solid var(--border-dim)',
      display: 'flex',
      alignItems: 'center',
      gap: 6,
      flexShrink: 0,
    }}>
      <span
        draggable={!!onDragStart}
        onDragStart={onDragStart}
        title="Drag to reorder"
        style={{
          cursor: onDragStart ? 'grab' : 'default',
          color: 'var(--border-bright)',
          fontSize: 13,
          userSelect: 'none',
          flexShrink: 0,
          letterSpacing: '-1px',
        }}
      >⠿</span>
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
      <span style={{ flex: 1 }} />
      {onMoveLeft && (
        <button onClick={onMoveLeft} title="Move pane left" style={CTRL_BTN_STYLE}>◀</button>
      )}
      {onMoveRight && (
        <button onClick={onMoveRight} title="Move pane right" style={CTRL_BTN_STYLE}>▶</button>
      )}
      {onClose && (
        <button onClick={onClose} title="Close pane" style={CTRL_BTN_STYLE}>×</button>
      )}
    </div>
  )
}

const CTRL_BTN_STYLE: React.CSSProperties = {
  padding: '1px 5px',
  fontSize: 10,
  color: 'var(--text-muted)',
  border: '1px solid var(--border-dim)',
  borderRadius: 2,
  lineHeight: 1,
  flexShrink: 0,
}

function PlaceholderPane({
  title, badge, onClose, onDragStart, onMoveLeft, onMoveRight,
}: {
  title: string; badge?: string;
  onClose?: () => void; onDragStart?: (e: React.DragEvent) => void;
  onMoveLeft?: () => void; onMoveRight?: () => void;
}) {
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
      <PaneHeader title={title} badge={badge} onClose={onClose} onDragStart={onDragStart} onMoveLeft={onMoveLeft} onMoveRight={onMoveRight} />
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
