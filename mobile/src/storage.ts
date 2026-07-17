import { Platform } from 'react-native'
import * as SecureStore from 'expo-secure-store'

/**
 * Cross-platform secret storage.
 *
 * Native (iOS/Android): the OS keychain/keystore via expo-secure-store.
 * Web: expo-secure-store has no web implementation, so we fall back to
 * localStorage. (localStorage is not encrypted at rest — acceptable for a JWT
 * on this tutorial app, but noted so nobody assumes keychain-grade secrecy on
 * the web build.)
 */

const isWeb = Platform.OS === 'web'

export async function getItem(key: string): Promise<string | null> {
  if (isWeb) {
    try {
      return globalThis.localStorage?.getItem(key) ?? null
    } catch {
      return null
    }
  }
  return SecureStore.getItemAsync(key)
}

export async function setItem(key: string, value: string): Promise<void> {
  if (isWeb) {
    try {
      globalThis.localStorage?.setItem(key, value)
    } catch {
      /* storage unavailable (private mode) — session stays in memory only */
    }
    return
  }
  await SecureStore.setItemAsync(key, value)
}

export async function deleteItem(key: string): Promise<void> {
  if (isWeb) {
    try {
      globalThis.localStorage?.removeItem(key)
    } catch {
      /* ignore */
    }
    return
  }
  await SecureStore.deleteItemAsync(key)
}
