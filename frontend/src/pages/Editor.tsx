import CodeMirror from '@uiw/react-codemirror'
import { python } from '@codemirror/lang-python'
import { oneDark } from '@codemirror/theme-one-dark'
import { useState } from 'react'
import { compile, clearToken, CompileResponse, LineMapping } from '../api'
import { useNavigate } from 'react-router-dom'
import CodePane from '../components/CodePane'

const STARTER = `# Welcome! Write Python below and click Compile.
x = 10
y = 20

for i in range(5):
    x += i

if x > 30:
    print(x)
else:
    print(y)
`

export default function EditorPage() {
  const [code, setCode] = useState(STARTER)
  const [result, setResult] = useState<CompileResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [activePyLine, setActivePyLine] = useState<number | null>(null)
  const nav = useNavigate()

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

  function handleLogout() {
    clearToken()
    nav('/login')
  }

  // Build color highlight maps for each pane
  const pyHighlight: Record<number, string> = {}
  const cHighlight: Record<number, string> = {}
  const asmHighlight: Record<number, string> = {}

  if (result) {
    for (const [pyLineStr, mapping] of Object.entries(result.line_map)) {
      const m = mapping as LineMapping
      const pyLine = Number(pyLineStr)
      pyHighlight[pyLine] = m.color
      for (const cl of m.c_lines) cHighlight[cl] = m.color
      for (const al of m.asm_lines) asmHighlight[al] = m.color
    }
  }

  // Active lines when a python line is clicked
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: '#0f1117' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', padding: '12px 20px', background: '#1a1d2e', borderBottom: '1px solid #2d3148', gap: 16 }}>
        <span style={{ fontWeight: 800, fontSize: 18, color: '#7c6af5', letterSpacing: '-0.02em' }}>
          ASM<span style={{ color: '#e2e8f0' }}>Tutorial</span>
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ fontSize: 12, color: '#64748b' }}>Click any Python line to trace it through C → Assembly</span>
        <button
          onClick={handleCompile}
          disabled={loading}
          style={{ background: '#7c6af5', color: 'white', padding: '8px 20px' }}
        >
          {loading ? 'Compiling…' : '▶ Compile'}
        </button>
        <button onClick={handleLogout} style={{ background: '#2d3148', color: '#94a3b8' }}>
          Logout
        </button>
      </div>

      {error && (
        <div style={{ background: '#7f1d1d', color: '#fca5a5', padding: '8px 20px', fontSize: 13 }}>
          {error}
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', gap: 8, padding: 8 }}>
        {/* Python editor */}
        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0, background: '#12151f', borderRadius: 8, overflow: 'hidden', border: '1px solid #2d3148' }}>
          <div style={{ padding: '10px 16px', background: '#1a1d2e', borderBottom: '1px solid #2d3148' }}>
            <span style={{ fontWeight: 700, fontSize: 13, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Python</span>
            <span style={{ marginLeft: 8, background: '#22c55e22', color: '#4ade80', borderRadius: 4, padding: '1px 8px', fontSize: 11, fontWeight: 600 }}>INPUT</span>
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            <CodeMirror
              value={code}
              onChange={setCode}
              extensions={[python()]}
              theme={oneDark}
              style={{ height: '100%', fontSize: 13 }}
              basicSetup={{ lineNumbers: true, foldGutter: false }}
            />
          </div>
        </div>

        {/* C pane */}
        {result ? (
          <CodePane
            title="C"
            badge="TRANSPILED"
            lines={result.c_lines}
            highlightMap={cHighlight}
            activeLines={activeCLines}
          />
        ) : (
          <PlaceholderPane title="C" message="Click Compile to see C output" />
        )}

        {/* Assembly pane */}
        {result ? (
          <CodePane
            title="x86 Assembly"
            badge="GCC -O0"
            lines={result.asm_lines}
            highlightMap={asmHighlight}
            activeLines={activeAsmLines}
          />
        ) : (
          <PlaceholderPane title="x86 Assembly" message="Click Compile to see Assembly output" />
        )}
      </div>

      {/* Python line color legend — shown only after compile */}
      {result && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '8px 12px', background: '#1a1d2e', borderTop: '1px solid #2d3148' }}>
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
                  background: isActive ? mapping.color : `${mapping.color}33`,
                  color: isActive ? '#0f1117' : mapping.color,
                  border: `1px solid ${mapping.color}`,
                  borderRadius: 4,
                  padding: '2px 10px',
                  fontSize: 11,
                  fontFamily: 'monospace',
                  maxWidth: 200,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  fontWeight: isActive ? 700 : 400,
                }}
                title={`Line ${pyLine}: ${line}`}
              >
                {pyLine}: {line.trim().slice(0, 28)}{line.trim().length > 28 ? '…' : ''}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

function PlaceholderPane({ title, message }: { title: string; message: string }) {
  return (
    <div style={{ flex: 1, minWidth: 0, background: '#12151f', borderRadius: 8, border: '1px solid #2d3148', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '10px 16px', background: '#1a1d2e', borderBottom: '1px solid #2d3148' }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{title}</span>
      </div>
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#334155', fontSize: 13 }}>
        {message}
      </div>
    </div>
  )
}
