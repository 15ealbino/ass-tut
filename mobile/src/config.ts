import { Platform } from 'react-native'
import Constants from 'expo-constants'
import AsyncStorage from '@react-native-async-storage/async-storage'

/**
 * Base URL of the backend API.
 *
 * Order of precedence:
 *   1. A URL the user saved in-app (Settings sheet on the login screen).
 *   2. `expo.extra.apiBaseUrl` from app.json (baked into each build).
 *   3. A platform default.
 *
 * On the **web build** the app is served from the same origin as the backend
 * proxy (nginx forwards `/api/*` → backend), so a relative `/api` avoids CORS
 * entirely. **Native** builds have no origin and need an absolute URL.
 */
const DEFAULT_API_BASE_URL =
  Platform.OS === 'web'
    ? '/api'
    : (Constants.expoConfig?.extra?.apiBaseUrl as string | undefined) ??
      'https://assembly-tutorial.com/api'

const OVERRIDE_KEY = 'cyberasm.apiBaseUrl'

let _cached: string | null = null

export async function getApiBaseUrl(): Promise<string> {
  if (_cached) return _cached
  const stored = await AsyncStorage.getItem(OVERRIDE_KEY)
  _cached = (stored && stored.trim()) || DEFAULT_API_BASE_URL
  return _cached
}

export async function setApiBaseUrl(url: string): Promise<void> {
  const clean = url.trim().replace(/\/+$/, '')
  _cached = clean || DEFAULT_API_BASE_URL
  if (clean) await AsyncStorage.setItem(OVERRIDE_KEY, clean)
  else await AsyncStorage.removeItem(OVERRIDE_KEY)
}

export function defaultApiBaseUrl(): string {
  return DEFAULT_API_BASE_URL
}
