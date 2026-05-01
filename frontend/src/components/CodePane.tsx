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
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      flex: 1,
      minWidth: 0,
      background: 'var(--bg-panel)',
      borderRadius: 2,
      overflow: 'hidden',
      border: '1px solid var(--border-dim)',
    }}>
      {/* Pane title bar */}
      <div style={{
        padding: '7px 14px',
        background: 'var(--bg-header)',
        borderBottom: '1px solid var(--border-dim)',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}>
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
            background: 'var(--cyan)18',
            color: 'var(--cyan)',
            border: '1px solid var(--cyan)44',
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
      </div>

      {/* Line list */}
      <div style={{ overflowY: 'auto', flex: 1, padding: '4px 0' }}>
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
                background: isActive && color ? `${color}18` : 'transparent',
                boxShadow: isActive && color ? `inset 0 0 12px ${color}11` : 'none',
                transition: 'background 0.1s, box-shadow 0.1s',
              }}
            >
              {/* Color stripe */}
              <div style={{
                width: 3,
                flexShrink: 0,
                background: color ?? 'transparent',
                opacity: isActive ? 1 : color ? 0.5 : 0,
                boxShadow: isActive && color ? `0 0 6px ${color}` : 'none',
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

              {/* Code text */}
              <pre style={{
                flex: 1,
                fontSize: 12,
                fontFamily: '"Fira Code", "Cascadia Code", monospace',
                lineHeight: '22px',
                color: isActive ? '#e8ffe8' : 'var(--text-primary)',
                margin: 0,
                paddingRight: 12,
                whiteSpace: 'pre',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                textShadow: isActive && color ? `0 0 8px ${color}66` : 'none',
              }}>
                {line}
              </pre>
            </div>
          )
        })}
      </div>
    </div>
  )
}
