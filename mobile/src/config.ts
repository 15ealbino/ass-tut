import Constants from 'expo-constants'
import AsyncStorage from '@react-native-async-storage/async-storage'

/**
 * Base URL of the backend API.
 *
 * Order of precedence:
 *   1. A URL the user saved in-app (Settings sheet on the login screen).
 *   2. `expo.extra.apiBaseUrl` from app.json (baked into each build).
 *   3. The production fallback below.
 *
 * The web app talks to a same-origin `/api`; the mobile app has no origin,
 * so it needs an absolute URL. Point this at your deployed backend.
 */
const DEFAULT_API_BASE_URL =
  (Constants.expoConfig?.extra?.apiBaseUrl as string | undefined) ??
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
