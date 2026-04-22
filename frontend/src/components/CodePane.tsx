import { LineMapping } from '../api'

interface Props {
  title: string
  lines: string[]
  highlightMap: Record<number, string>   // 1-indexed line → color
  activeLines: Set<number>               // 1-indexed lines currently "active"
  onLineClick?: (lineNo: number) => void
  badge?: string
}

export default function CodePane({ title, lines, highlightMap, activeLines, onLineClick, badge }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0, background: '#12151f', borderRadius: 8, overflow: 'hidden', border: '1px solid #2d3148' }}>
      <div style={{ padding: '10px 16px', background: '#1a1d2e', borderBottom: '1px solid #2d3148', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{title}</span>
        {badge && <span style={{ background: '#7c6af522', color: '#7c6af5', borderRadius: 4, padding: '1px 8px', fontSize: 11, fontWeight: 600 }}>{badge}</span>}
      </div>
      <div style={{ overflowY: 'auto', flex: 1, padding: '8px 0' }}>
        {lines.map((line, i) => {
          const lineNo = i + 1
          const color = highlightMap[lineNo]
          const isActive = activeLines.has(lineNo)
          return (
            <div
              key={lineNo}
              onClick={() => onLineClick?.(lineNo)}
              style={{
                display: 'flex',
                alignItems: 'stretch',
                cursor: onLineClick ? 'pointer' : 'default',
                background: isActive && color ? `${color}22` : 'transparent',
                transition: 'background 0.12s',
              }}
            >
              {/* color stripe */}
              <div style={{
                width: 4,
                flexShrink: 0,
                background: color ?? 'transparent',
                opacity: isActive ? 1 : color ? 0.35 : 0,
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
                paddingRight: 12,
                whiteSpace: 'pre',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}>{line}</pre>
            </div>
          )
        })}
      </div>
    </div>
  )
}
