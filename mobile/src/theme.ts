/**
 * CYBER//ASM dark palette — mirrors the web frontend's CSS custom properties
 * (frontend/src/index.css) so the mobile app reads as the same product.
 */
import { Platform } from 'react-native'

export const colors = {
  bgBase: '#050a0e',
  bgPanel: '#080d12',
  bgHeader: '#060b0f',
  borderDim: '#0d2a1a',
  borderMid: '#174d2a',
  borderBright: '#1f6b38',
  green: '#00ff41',
  greenDim: '#00aa2a',
  greenFaint: '#003310',
  cyan: '#00e5ff',
  cyanDim: '#0099aa',
  red: '#ff003c',
  redDim: '#660018',
  textPrimary: '#b8ffcc',
  textDim: '#2f6642',
  textMuted: '#1a4028',
}

/**
 * A monospace stack. React Native cannot use the web's `Fira Code`
 * unless it is bundled as a custom font (see README → "Fonts"); until then we
 * fall back to each platform's built-in monospace face.
 */
export const mono = Platform.select({
  ios: 'Menlo',
  android: 'monospace',
  default: 'monospace',
}) as string

export const severityColor: Record<string, string> = {
  CRITICAL: colors.red,
  HIGH: '#ff8c00',
  MEDIUM: colors.cyan,
}
