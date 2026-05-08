import { useState } from 'react'

export interface AsmLineInfo {
  pyLine: number
  pyCode: string
  color: string
}

export interface VulnAdvisory {
  name: string
  severity: string
  explanation: string
}

interface Props {
  title: string
  lines: string[]
  highlightMap: Record<number, string>
  activeLines: Set<number>
  infoMap: Record<number, AsmLineInfo>
  badge?: string
  vuln?: VulnAdvisory | null
  onClose?: () => void
  onDragStart?: (e: React.DragEvent<HTMLElement>) => void
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
  negl: "negate (two's complement)",
  cdq: 'sign-extend eax → edx:eax',
  cltd: 'sign-extend for divide',
  nop: 'no operation',
  endbr32: 'control-flow enforcement hint',
  endbr64: 'control-flow enforcement hint',
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'var(--red)',
  HIGH: '#ff8c00',
  MEDIUM: 'var(--cyan)',
}

function explainAsm(line: string): string {
  const t = line.trim()
  if (!t || t.startsWith('.') || t.endsWith(':')) return ''
  const mnemonic = t.split(/[\s,]/)[0].toLowerCase()
  return MNEMONIC_MAP[mnemonic] ?? ''
}

export default function AsmPane({ title, lines, highlightMap, activeLines, infoMap, badge, vuln, onClose, onDragStart }: Props) {
  const [advisoryOpen, setAdvisoryOpen] = useState(true)
  const sevColor = vuln ? (SEVERITY_COLOR[vuln.severity] ?? 'var(--red)') : 'var(--red)'

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      flex: 1,
      minWidth: 0,
      background: 'var(--bg-panel)',
      borderRadius: 2,
      overflow: 'hidden',
      border: vuln ? `1px solid ${sevColor}55` : '1px solid var(--border-dim)',
      boxShadow: vuln ? `0 0 14px ${sevColor}22` : 'none',
      transition: 'border-color 0.2s, box-shadow 0.2s',
    }}>

      {/* Pane title bar */}
      <div style={{
        padding: '7px 14px',
        background: 'var(--bg-header)',
        borderBottom: '1px solid var(--border-dim)',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
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
            background: '#00ff4118',
            color: 'var(--green)',
            border: '1px solid #00ff4144',
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
        <span style={{
          marginLeft: 'auto',
          fontSize: 10,
          color: 'var(--text-muted)',
          letterSpacing: '0.06em',
          fontFamily: 'Fira Code, monospace',
        }}>
          CLICK LEGEND TO TRACE
        </span>
        {onClose && (
          <button
            onClick={onClose}
            title="Close pane"
            style={{
              padding: '1px 6px',
              fontSize: 11,
              color: 'var(--text-muted)',
              border: '1px solid var(--border-dim)',
              borderRadius: 2,
              lineHeight: 1,
            }}
          >×</button>
        )}
      </div>

      {/* Security advisory banner — only shown when a vuln is active */}
      {vuln && (
        <div style={{
          background: '#1a0008',
          borderLeft: `3px solid ${sevColor}`,
          borderBottom: `1px solid ${sevColor}55`,
          boxShadow: `inset 0 0 20px ${sevColor}0a, 0 2px 8px ${sevColor}22`,
          flexShrink: 0,
        }}>
          {/* Advisory header row */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 10px',
          }}>
            <span style={{
              fontSize: 10,
              fontWeight: 700,
              color: sevColor,
              fontFamily: 'Fira Code, monospace',
              letterSpacing: '0.08em',
              flex: 1,
            }}>
              [!] SECURITY ADVISORY :: {vuln.name}
            </span>
            <span style={{
              fontSize: 8,
              fontWeight: 700,
              color: sevColor,
              border: `1px solid ${sevColor}`,
              borderRadius: 2,
              padding: '1px 5px',
              fontFamily: 'Fira Code, monospace',
              letterSpacing: '0.08em',
              flexShrink: 0,
            }}>
              {vuln.severity}
            </span>
            {/* Collapse toggle */}
            <button
              onClick={() => setAdvisoryOpen(o => !o)}
              style={{
                fontSize: 10,
                color: 'var(--text-dim)',
                border: `1px solid var(--border-dim)`,
                padding: '1px 6px',
                flexShrink: 0,
              }}
              title={advisoryOpen ? 'Collapse advisory' : 'Expand advisory'}
            >
              {advisoryOpen ? '[-]' : '[+]'}
            </button>
          </div>

          {/* Advisory body */}
          {advisoryOpen && (
            <div style={{
              padding: '0 10px 8px 10px',
              fontSize: 11,
              color: 'var(--text-dim)',
              fontFamily: 'Fira Code, monospace',
              lineHeight: 1.6,
              letterSpacing: '0.02em',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}>
              {vuln.explanation}
            </div>
          )}
        </div>
      )}

      {/* Assembly line list */}
      <div style={{ overflowY: 'auto', flex: 1, padding: '4px 0' }}>
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
                background: isActive && color ? `${color}18` : 'transparent',
                boxShadow: isActive && color ? `inset 0 0 16px ${color}0d` : 'none',
                transition: 'background 0.1s',
              }}
            >
              {/* Color stripe */}
              <div style={{
                width: 3,
                flexShrink: 0,
                background: color ?? 'transparent',
                opacity: isActive ? 1 : color ? 0.7 : 0,
                boxShadow: isActive && color ? `0 0 8px ${color}` : 'none',
                transition: 'opacity 0.1s',
              }} />

              {/* Line number */}
              <div style={{
                width: 36,
                textAlign: 'right',
                paddingRight: 10,
                color: 'var(--text-muted)',
                fontSize: 11,
                fontFamily: 'Fira Code, monospace',
                userSelect: 'none',
                lineHeight: '22px',
                flexShrink: 0,
              }}>
                {lineNo}
              </div>

              {/* Assembly instruction */}
              <pre style={{
                flex: 1,
                fontSize: 12,
                fontFamily: '"Fira Code", "Cascadia Code", monospace',
                lineHeight: '22px',
                color: isActive ? '#ccffcc' : 'var(--text-primary)',
                margin: 0,
                paddingRight: 8,
                whiteSpace: 'pre',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                textShadow: isActive && color ? `0 0 8px ${color}55` : 'none',
              }}>
                {line}
              </pre>

              {/* Annotation column */}
              <div style={{
                width: 220,
                flexShrink: 0,
                display: 'flex',
                alignItems: 'center',
                gap: 5,
                paddingLeft: 8,
                paddingRight: 10,
                borderLeft: '1px solid var(--border-dim)',
                overflow: 'hidden',
              }}>
                {info && (
                  <span style={{
                    fontSize: 9,
                    fontWeight: 700,
                    color: info.color,
                    background: `${info.color}22`,
                    border: `1px solid ${info.color}44`,
                    borderRadius: 2,
                    padding: '1px 5px',
                    flexShrink: 0,
                    fontFamily: 'Fira Code, monospace',
                    letterSpacing: '0.04em',
                    boxShadow: isActive ? `0 0 4px ${info.color}55` : 'none',
                  }}>
                    PY:{info.pyLine}
                  </span>
                )}
                {explanation && (
                  <span style={{
                    fontSize: 10,
                    color: isActive ? 'var(--cyan)' : 'var(--text-dim)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    fontFamily: 'Fira Code, monospace',
                    letterSpacing: '0.02em',
                    textShadow: isActive ? 'var(--glow-cyan)' : 'none',
                  }}>
                    // {explanation}
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
