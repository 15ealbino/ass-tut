import React from 'react'
import { View, Text, Pressable, ScrollView, StyleSheet } from 'react-native'
import { colors, mono } from '../theme'

interface Props {
  title: string
  badge?: string
  lines: string[]
  /** 1-indexed line number → color hex */
  highlightMap: Record<number, string>
  /** 1-indexed lines currently "active" (from the selected Python line) */
  activeLines: Set<number>
  onLinedPress?: (lineNo: number) => void
}

/**
 * A read-only code pane: a color stripe + line number + monospace text per row,
 * mirroring the web component (frontend/src/components/CodePane.tsx). Long lines
 * scroll horizontally; the whole pane scrolls vertically.
 */
export default function CodePane({
  title,
  badge,
  lines,
  highlightMap,
  activeLines,
  onLinedPress,
}: Props) {
  return (
    <View style={styles.pane}>
      <View style={styles.titleBar}>
        <Text style={styles.title}>{'>_ ' + title}</Text>
        {badge ? (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>{badge}</Text>
          </View>
        ) : null}
      </View>

      <ScrollView style={styles.body} contentContainerStyle={styles.bodyContent}>
        <ScrollView horizontal showsHorizontalScrollIndicator={false}>
          <View>
            {lines.map((line, i) => {
              const lineNo = i + 1
              const color = highlightMap[lineNo]
              const isActive = activeLines.has(lineNo)
              return (
                <Pressable
                  key={lineNo}
                  onPress={() => onLinedPress?.(lineNo)}
                  style={[
                    styles.row,
                    isActive && color ? { backgroundColor: color + '22' } : null,
                  ]}
                >
                  <View
                    style={[
                      styles.stripe,
                      {
                        backgroundColor: color ?? 'transparent',
                        opacity: isActive ? 1 : color ? 0.5 : 0,
                      },
                    ]}
                  />
                  <Text style={styles.lineNo}>{lineNo}</Text>
                  <Text
                    style={[
                      styles.code,
                      { color: isActive ? '#e8ffe8' : colors.textPrimary },
                    ]}
                  >
                    {line.length ? line : ' '}
                  </Text>
                </Pressable>
              )
            })}
          </View>
        </ScrollView>
      </ScrollView>
    </View>
  )
}

const styles = StyleSheet.create({
  pane: {
    flex: 1,
    backgroundColor: colors.bgPanel,
    borderRadius: 2,
    borderWidth: 1,
    borderColor: colors.borderDim,
    overflow: 'hidden',
  },
  titleBar: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingVertical: 7,
    paddingHorizontal: 12,
    backgroundColor: colors.bgHeader,
    borderBottomWidth: 1,
    borderBottomColor: colors.borderDim,
  },
  title: {
    fontFamily: mono,
    fontWeight: '700',
    fontSize: 11,
    letterSpacing: 1.4,
    color: colors.textDim,
    textTransform: 'uppercase',
  },
  badge: {
    borderWidth: 1,
    borderColor: colors.cyan + '44',
    backgroundColor: colors.cyan + '18',
    borderRadius: 2,
    paddingHorizontal: 6,
    paddingVertical: 1,
  },
  badgeText: {
    color: colors.cyan,
    fontFamily: mono,
    fontSize: 9,
    fontWeight: '700',
    letterSpacing: 1,
  },
  body: { flex: 1 },
  bodyContent: { paddingVertical: 4 },
  row: {
    flexDirection: 'row',
    alignItems: 'stretch',
    minWidth: '100%',
  },
  stripe: {
    width: 3,
  },
  lineNo: {
    width: 34,
    textAlign: 'right',
    paddingRight: 8,
    color: colors.textMuted,
    fontSize: 11,
    lineHeight: 22,
    fontFamily: mono,
  },
  code: {
    fontFamily: mono,
    fontSize: 12,
    lineHeight: 22,
    paddingRight: 16,
  },
})
