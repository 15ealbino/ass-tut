import CodeMirror from '@uiw/react-codemirror'
import { python } from '@codemirror/lang-python'
import { oneDark } from '@codemirror/theme-one-dark'
import type { EditorView } from '@codemirror/view'
import { useState, useRef } from 'react'
import { compile, CompileMethod, CompileResponse, LineMapping } from '../api'
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