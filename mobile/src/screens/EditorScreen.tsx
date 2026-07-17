import React, { useMemo, useState } from 'react'
import {
  View,
  Text,
  TextInput,
  Pressable,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  Modal,
  FlatList,
} from 'react-native'
import { SafeAreaView } from 'react-native-safe-area-context'
import { compile, CompileMethod, CompileResponse, LineMapping } from '../api'
import { useAuth } from '../context/AuthContext'
import CodePane from '../components/CodePane'
import { STARTER, SNIPPETS, Snippet } from '../data/snippets'
import { colors, mono, severityColor } from '../theme'

type PaneKey = 'python' | 'c' | 'asm'

export default function EditorScreen() {
  const { signOut } = useAuth()
  const [code, setCode] = useState(STARTER)
  const [result, setResult] = useState<CompileResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [method, setMethod] = useState<CompileMethod>('transpile')
  const [activePyLine, setActivePyLine] = useState<number | null>(null)
  const [pane, setPane] = useState<PaneKey>('python')
  const [showExamples, setShowExamples] = useState(false)

  async function runCompile() {
    setLoading(true)
    setError('')
    setActivePyLine(null)
    try {
      const res = await compile(code, method)
      setResult(res)
      setPane('python')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Compile failed')
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  // ── Build highlight maps + reverse lookups (mirrors the web Editor) ──
  const maps = useMemo(() => {
    const pyHighlight: Record<number, string> = {}
    const cHighlight: Record<number, string> = {}
    const asmHighlight: Record<number, string> = {}
    const cToPy: Record<number, number> = {}
    const asmToPy: Record<number, number> = {}

    if (result) {
      for (const [pyLineStr, mapping] of Object.entries(result.line_map)) {
        const m = mapping as LineMapping
        const pyLine = Number(pyLineStr)
        pyHighlight[pyLine] = m.color
        for (const cl of m.c_lines) {
          cHighlight[cl] = m.color
          cToPy[cl] = pyLine
        }
        for (const al of m.asm_lines) {
          asmHighlight[al] = m.color
          asmToPy[al] = pyLine
        }
      }
    }
    return { pyHighlight, cHighlight, asmHighlight, cToPy, asmToPy }
  }, [result])

  const activeSets = useMemo(() => {
    const c = new Set<number>()
    const asm = new Set<number>()
    if (activePyLine && result) {
      const m = result.line_map[activePyLine] as LineMapping | undefined
      if (m) {
        m.c_lines.forEach((l) => c.add(l))
        m.asm_lines.forEach((l) => asm.add(l))
      }
    }
    return { c, asm }
  }, [activePyLine, result])

  const activePy = activePyLine ? new Set([activePyLine]) : new Set<number>()

  function loadSnippet(s: Snippet) {
    setCode(s.code)
    setResult(null)
    setError('')
    setActivePyLine(null)
    setPane('python')
    setShowExamples(false)
  }

  const badge =
    method === 'pyghidra'
      ? pane === 'asm'
        ? 'NUITKA + GHIDRA'
        : 'GHIDRA DECOMP'
      : pane === 'asm'
        ? 'GCC -O0'
        : 'TRANSPILED'

  return (
    <SafeAreaView style={styles.root} edges={['top', 'left', 'right']}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.brand}>
          <Text style={{ color: colors.green }}>CYBER</Text>
          <Text style={{ color: colors.textDim }}>//</Text>
          <Text style={{ color: colors.cyan }}>ASM</Text>
        </Text>
        <View style={{ flex: 1 }} />
        {loading ? (
          <Text style={styles.statusCyan}>◈ COMPILING</Text>
        ) : result ? (
          <Text style={styles.statusGreen}>◉ OK</Text>
        ) : null}
        <Pressable onPress={signOut} hitSlop={8}>
          <Text style={styles.signOut}>EXIT</Text>
        </Pressable>
      </View>

      {/* Toolbar */}
      <View style={styles.toolbar}>
        <View style={styles.methodRow}>
          {(['transpile', 'pyghidra'] as CompileMethod[]).map((m) => {
            const on = method === m
            const c = m === 'pyghidra' ? colors.cyan : colors.green
            return (
              <Pressable
                key={m}
                onPress={() => setMethod(m)}
                style={[
                  styles.methodChip,
                  { borderColor: on ? c : colors.borderDim },
                  on && { backgroundColor: c + '18' },
                ]}
              >
                <Text style={[styles.methodChipText, { color: on ? c : colors.textDim }]}>
                  {m === 'pyghidra' ? 'NUITKA→GHIDRA' : 'TRANSPILE→GCC'}
                </Text>
              </Pressable>
            )
          })}
        </View>
        <Pressable style={styles.examplesBtn} onPress={() => setShowExamples(true)}>
          <Text style={styles.examplesBtnText}>VULN//LAB</Text>
        </Pressable>
      </View>

      {/* Pane switcher (only meaningful after a compile) */}
      <View style={styles.tabs}>
        {(['python', 'c', 'asm'] as PaneKey[]).map((p) => {
          const on = pane === p
          const disabled = p !== 'python' && !result
          return (
            <Pressable
              key={p}
              disabled={disabled}
              onPress={() => setPane(p)}
              style={[styles.tab, on && styles.tabOn]}
            >
              <Text
                style={[
                  styles.tabText,
                  on && styles.tabTextOn,
                  disabled && { opacity: 0.3 },
                ]}
              >
                {p === 'python' ? 'PYTHON' : p === 'c' ? 'C' : 'ASM'}
              </Text>
            </Pressable>
          )
        })}
      </View>

      {/* Body */}
      <View style={styles.body}>
        {pane === 'python' ? (
          <View style={styles.editorWrap}>
            <ScrollView style={styles.editorScroll} keyboardShouldPersistTaps="handled">
              <TextInput
                style={styles.editor}
                value={code}
                onChangeText={setCode}
                multiline
                autoCapitalize="none"
                autoCorrect={false}
                spellCheck={false}
                placeholder="# Write Python here"
                placeholderTextColor={colors.textMuted}
                textAlignVertical="top"
              />
            </ScrollView>
            {result ? (
              <Text style={styles.traceHint}>
                Switch to C / ASM and tap a line to trace it back to Python.
              </Text>
            ) : null}
          </View>
        ) : pane === 'c' ? (
          <CodePane
            title="C"
            badge={badge}
            lines={result?.c_lines ?? []}
            highlightMap={maps.cHighlight}
            activeLines={activeSets.c}
            onLinedPress={(ln) => {
              const py = maps.cToPy[ln]
              if (py) setActivePyLine(py)
            }}
          />
        ) : (
          <CodePane
            title="ASSEMBLY"
            badge={badge}
            lines={result?.asm_lines ?? []}
            highlightMap={maps.asmHighlight}
            activeLines={activeSets.asm}
            onLinedPress={(ln) => {
              const py = maps.asmToPy[ln]
              if (py) setActivePyLine(py)
            }}
          />
        )}
      </View>

      {/* Error banner */}
      {error ? (
        <View style={styles.errorBar}>
          <Text style={styles.errorText}>⚠ {error}</Text>
        </View>
      ) : null}

      {/* Python-line legend — tap to trace across panes */}
      {result && pane !== 'python' ? (
        <View style={styles.legend}>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            {Object.entries(result.line_map).map(([pyStr, m]) => {
              const py = Number(pyStr)
              const on = activePyLine === py
              const mm = m as LineMapping
              return (
                <Pressable
                  key={py}
                  onPress={() => setActivePyLine(on ? null : py)}
                  style={[
                    styles.chip,
                    { borderColor: mm.color + (on ? 'ff' : '55') },
                    on && { backgroundColor: mm.color + '22' },
                  ]}
                >
                  <View style={[styles.chipDot, { backgroundColor: mm.color }]} />
                  <Text style={styles.chipText}>
                    py:{py} {(result.python_lines[py - 1] ?? '').trim().slice(0, 16)}
                  </Text>
                </Pressable>
              )
            })}
          </ScrollView>
        </View>
      ) : null}

      {/* Compile button */}
      <Pressable
        style={[styles.compileBtn, loading && { opacity: 0.5 }]}
        onPress={runCompile}
        disabled={loading}
      >
        {loading ? (
          <ActivityIndicator color={colors.green} />
        ) : (
          <Text style={styles.compileBtnText}>▶ COMPILE</Text>
        )}
      </Pressable>

      {/* Examples modal */}
      <Modal
        visible={showExamples}
        animationType="slide"
        transparent
        onRequestClose={() => setShowExamples(false)}
      >
        <View style={styles.modalBackdrop}>
          <View style={styles.modalSheet}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>VULN//LAB</Text>
              <Pressable onPress={() => setShowExamples(false)} hitSlop={8}>
                <Text style={styles.modalClose}>×</Text>
              </Pressable>
            </View>
            <FlatList
              data={SNIPPETS}
              keyExtractor={(s) => s.id}
              renderItem={({ item }) => (
                <Pressable style={styles.snippetRow} onPress={() => loadSnippet(item)}>
                  <View style={styles.snippetHead}>
                    <Text style={styles.snippetName}>{item.name}</Text>
                    <Text
                      style={[
                        styles.severity,
                        { color: severityColor[item.severity] ?? colors.cyan },
                      ]}
                    >
                      {item.severity}
                    </Text>
                  </View>
                  <Text style={styles.snippetCat}>{item.category}</Text>
                  <Text style={styles.snippetDesc}>{item.description}</Text>
                </Pressable>
              )}
            />
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  )
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgBase },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingHorizontal: 16,
    paddingVertical: 10,
    backgroundColor: colors.bgHeader,
    borderBottomWidth: 1,
    borderBottomColor: colors.borderMid,
  },
  brand: { fontFamily: mono, fontSize: 16, fontWeight: '700', letterSpacing: 2 },
  statusCyan: { color: colors.cyan, fontFamily: mono, fontSize: 11 },
  statusGreen: { color: colors.green, fontFamily: mono, fontSize: 11 },
  signOut: {
    color: colors.textDim,
    fontFamily: mono,
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 1,
  },
  toolbar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 12,
    paddingVertical: 8,
    gap: 8,
  },
  methodRow: { flexDirection: 'row', gap: 6, flexShrink: 1 },
  methodChip: {
    borderWidth: 1,
    borderRadius: 2,
    paddingHorizontal: 8,
    paddingVertical: 6,
  },
  methodChipText: { fontFamily: mono, fontSize: 10, fontWeight: '700', letterSpacing: 0.5 },
  examplesBtn: {
    borderWidth: 1,
    borderColor: colors.red + '66',
    backgroundColor: colors.red + '11',
    borderRadius: 2,
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  examplesBtnText: { color: colors.red, fontFamily: mono, fontSize: 10, fontWeight: '700', letterSpacing: 1 },
  tabs: {
    flexDirection: 'row',
    paddingHorizontal: 12,
    gap: 4,
  },
  tab: {
    paddingHorizontal: 14,
    paddingVertical: 7,
    borderBottomWidth: 2,
    borderBottomColor: 'transparent',
  },
  tabOn: { borderBottomColor: colors.green },
  tabText: { fontFamily: mono, fontSize: 11, color: colors.textDim, letterSpacing: 1, fontWeight: '700' },
  tabTextOn: { color: colors.green },
  body: { flex: 1, paddingHorizontal: 12, paddingTop: 6 },
  editorWrap: {
    flex: 1,
    borderWidth: 1,
    borderColor: colors.borderDim,
    borderRadius: 2,
    backgroundColor: colors.bgPanel,
    overflow: 'hidden',
  },
  editorScroll: { flex: 1 },
  editor: {
    flex: 1,
    minHeight: 260,
    color: colors.textPrimary,
    fontFamily: mono,
    fontSize: 13,
    lineHeight: 20,
    padding: 12,
  },
  traceHint: {
    fontFamily: mono,
    fontSize: 10,
    color: colors.textMuted,
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderTopWidth: 1,
    borderTopColor: colors.borderDim,
  },
  errorBar: {
    marginHorizontal: 12,
    marginTop: 6,
    borderWidth: 1,
    borderColor: colors.red + '66',
    backgroundColor: colors.red + '11',
    borderRadius: 2,
    padding: 10,
  },
  errorText: { color: colors.red, fontFamily: mono, fontSize: 12 },
  legend: {
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  chip: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    borderWidth: 1,
    borderRadius: 2,
    paddingHorizontal: 8,
    paddingVertical: 5,
    marginRight: 6,
  },
  chipDot: { width: 8, height: 8, borderRadius: 1 },
  chipText: { fontFamily: mono, fontSize: 10, color: colors.textPrimary },
  compileBtn: {
    margin: 12,
    borderWidth: 1,
    borderColor: colors.green,
    backgroundColor: colors.greenFaint,
    borderRadius: 2,
    paddingVertical: 14,
    alignItems: 'center',
  },
  compileBtnText: {
    color: colors.green,
    fontFamily: mono,
    fontWeight: '700',
    fontSize: 14,
    letterSpacing: 2,
  },
  modalBackdrop: { flex: 1, backgroundColor: '#000000cc', justifyContent: 'flex-end' },
  modalSheet: {
    maxHeight: '80%',
    backgroundColor: colors.bgPanel,
    borderTopWidth: 1,
    borderColor: colors.borderMid,
    borderTopLeftRadius: 8,
    borderTopRightRadius: 8,
  },
  modalHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: colors.borderDim,
  },
  modalTitle: { color: colors.red, fontFamily: mono, fontSize: 14, fontWeight: '700', letterSpacing: 2 },
  modalClose: { color: colors.textDim, fontSize: 26, lineHeight: 26 },
  snippetRow: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: colors.borderDim,
  },
  snippetHead: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  snippetName: { color: colors.textPrimary, fontFamily: mono, fontSize: 12, fontWeight: '700', flexShrink: 1 },
  severity: { fontFamily: mono, fontSize: 9, fontWeight: '700', letterSpacing: 1, marginLeft: 8 },
  snippetCat: { color: colors.textDim, fontFamily: mono, fontSize: 10, marginTop: 3 },
  snippetDesc: { color: colors.textMuted, fontFamily: mono, fontSize: 10, marginTop: 4, lineHeight: 15 },
})
