import CodeMirror from '@uiw/react-codemirror'
import { python } from '@codemirror/lang-python'
import { oneDark } from '@codemirror/theme-one-dark'
import type { EditorView } from '@codemirror/view'
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
  const editorViewRef = useRef<EditorView | null>(null)

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
