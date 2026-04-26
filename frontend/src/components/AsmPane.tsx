export interface AsmLineInfo {
  pyLine: number
  pyCode: string
  color: string
}

interface Props {
  title: string
  lines: string[]
  highlightMap: Record<number, string>
  activeLines: Set<number>
  infoMap: Record<number, AsmLineInfo>
  badge?: string
}

const MNEMONIC_MAP: Record<string, string> = {
  movl: 'copy 32-bit value',
  movq: 'copy 64-bit value',
  movw: 'copy 16-bit value',
  movb: 'copy byte',
  pushl: 'push 32-bit onto stack',
  pushq: 'push 64-bit onto stack',
  popl: 'pop 32-bit from stack',
  popq: 'pop 64-bit from stack',
  call: 'call function',
  ret: 'return from function',
  leave: 'restore frame pointer',
  jmp: 'jump (unconditional)',
  je: 'jump if equal',
  jne: 'jump if not equal',
  jz: 'jump if zero',
  jnz: 'jump if not zero',
  jl: 'jump if less than',
  jle: 'jump if ≤',
  jg: 'jump if greater than',
  jge: 'jump if ≥',
  ja: 'jump if above (unsigned >)',
  jb: 'jump if below (unsigned <)',
  jae: 'jump if above or equal',
  jbe: 'jump if below or equal',
  addl: 'add (32-bit)',
  addq: 'add (64-bit)',
  subl: 'subtract (32-bit)',
  subq: 'subtract (64-bit)',
  imull: 'signed multiply (32-bit)',
  imulq: 'signed multiply (64-bit)',
  idivl: 'signed divide (32-bit)',
  idivq: 'signed divide (64-bit)',
  cmpl: 'compare 32-bit values',
  cmpq: 'compare 64-bit values',
  testl: 'bitwise AND test (32-bit)',
  testq: 'bitwise AND test (64-bit)',
  leal: 'load effective address (32-bit)',
  leaq: 'load effective address (64-bit)',
  xorl: 'XOR 32-bit (zero-init if same reg)',
  xorq: 'XOR 64-bit',
  andl: 'bitwise AND (32-bit)',
  andq: 'bitwise AND (64-bit)',
  orl: 'bitwise OR (32-bit)',
  orq: 'bitwise OR (64-bit)',
  sarl: 'arithmetic right shift (32-bit)',
  sarq: 'arithmetic right shift (64-bit)',
  shll: 'logical left shift (32-bit)',
  shlq: 'logical left shift (64-bit)',
  shrl: 'logical right shift (32-bit)',
  shrq: 'logical right shift (64-bit)',
  notl: 'bitwise NOT (32-bit)',
  negl: 'negate (two\'s complement)',
  cdq: 'sign-extend eax → edx:eax',
  cltd: 'sign-extend for divide',
  nop: 'no operation',
  endbr32: 'control-flow enforcement hint',
  endbr64: 'control-flow enforcement hint',
}

function explainAsm(line: string): string {
  const t = line.trim()
  if (!t || t.startsWith('.') || t.endsWith(':')) return ''
  const mnemonic = t.split(/[\s,]/)[0].toLowerCase()
  return MNEMONIC_MAP[mnemonic] ?? ''
}

export default function AsmPane({ title, lines, highlightMap, activeLines, infoMap, badge }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0, background: '#12151f', borderRadius: 8, overflow: 'hidden', border: '1px solid #2d3148' }}>
      {/* Header */}
      <div style={{ padding: '10px 16px', background: '#1a1d2e', borderBottom: '1px solid #2d3148', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{title}</span>
        {badge && <span style={{ background: '#7c6af522', color: '#7c6af5', borderRadius: 4, padding: '1px 8px', fontSize: 11, fontWeight: 600 }}>{badge}</span>}
        <span style={{ marginLeft: 'auto', fontSize: 11, color: '#475569' }}>click legend chip to highlight</span>
      </div>

      {/* Lines */}
      <div style={{ overflowY: 'auto', flex: 1, padding: '8px 0' }}>
        {lines.map((line, i) => {
          const lineNo = i + 1
          const color = highlightMap[lineNo]
          const isActive = activeLines.has(lineNo)
          const info = infoMap[lineNo]
          const explanation = explainAsm(line)

          return (
            <div
              key={lineNo}
              style={{
                display: 'flex',
                alignItems: 'stretch',
                background: isActive && color ? `${color}22` : 'transparent',
                transition: 'background 0.12s',
              }}
            >
              {/* color stripe */}
              <div style={{
                width: 4,
                flexShrink: 0,
                background: color ?? 'transparent',
                opacity: isActive ? 1 : color ? 0.8 : 0,
                transition: 'opacity 0.12s',
              }} />

              {/* line number */}
              <div style={{
                width: 36,
                textAlign: 'right',
                paddingRight: 10,
                color: '#4a5568',
                fontSize: 12,
                fontFamily: 'monospace',
                userSelect: 'none',
                lineHeight: '22px',
                flexShrink: 0,
              }}>{lineNo}</div>

              {/* code */}
              <pre style={{
                flex: 1,
                fontSize: 13,
                fontFamily: '"Fira Code", "Cascadia Code", monospace',
                lineHeight: '22px',
                color: isActive ? '#f8fafc' : '#cbd5e1',
                margin: 0,
                paddingRight: 8,
                whiteSpace: 'pre',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}>{line}</pre>

              {/* comment column */}
              <div style={{
                width: 210,
                flexShrink: 0,
                display: 'flex',
                alignItems: 'center',
                gap: 5,
                paddingRight: 10,
                borderLeft: '1px solid #1e2235',
                paddingLeft: 8,
                overflow: 'hidden',
              }}>
                {info && (
                  <span style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: info.color,
                    background: `${info.color}22`,
                    borderRadius: 3,
                    padding: '1px 5px',
                    flexShrink: 0,
                    fontFamily: 'monospace',
                  }}>
                    py.{info.pyLine}
                  </span>
                )}
                {explanation && (
                  <span style={{
                    fontSize: 11,
                    color: isActive ? '#94a3b8' : '#475569',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    fontFamily: 'system-ui, sans-serif',
                  }}>
                    {explanation}
                  </span>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
