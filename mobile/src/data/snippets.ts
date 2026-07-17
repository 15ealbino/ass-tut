/**
 * Starter code + a curated subset of the web app's VULN//LAB catalogue.
 * These are teaching demonstrations of classic memory-corruption patterns,
 * expressed in the limited Python subset the transpiler supports.
 */

export const STARTER = `# Write Python below and tap COMPILE
x = 10
y = 20

for i in range(5):
    x += i

if x > 30:
    print(x)
else:
    print(y)
`

export interface Snippet {
  id: string
  name: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  category: string
  description: string
  code: string
}

export const SNIPPETS: Snippet[] = [
  {
    id: 'stack-bof',
    name: 'STACK BUFFER OVERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Corruption',
    description: 'Loop smashes past a fixed stack frame, clobbering the return address.',
    code: `# CVE pattern: fixed stack buf[8], loop bound 64 — smashes return addr
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
    code: `# CVE pattern: object freed (zeroed), dangling field access follows
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
    code: `# CVE pattern: vtable-style handler pointer overwritten by attacker
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
    id: 'int-overflow',
    name: 'INTEGER OVERFLOW',
    severity: 'HIGH',
    category: 'Arithmetic',
    description: 'Undersized size calculation wraps around, under-allocating a buffer.',
    code: `# CVE pattern: size * count overflows, allocation smaller than expected
def alloc_size(count):
    element = 4096
    total = 0
    i = 0
    while i < count:
        total += element
        i += 1
    return total

size = alloc_size(16)
print(size)
`,
  },
  {
    id: 'off-by-one',
    name: 'OFF-BY-ONE',
    severity: 'MEDIUM',
    category: 'Memory Corruption',
    description: 'Loop bound uses <= instead of <, writing one slot past the buffer.',
    code: `# CVE pattern: <= bound writes one element past the buffer end
def fill(n):
    total = 0
    i = 0
    while i <= n:
        total += i
        i += 1
    return total

print(fill(8))
`,
  },
]
