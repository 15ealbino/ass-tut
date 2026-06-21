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