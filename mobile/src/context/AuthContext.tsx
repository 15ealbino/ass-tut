import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import * as SecureStore from 'expo-secure-store'
import { setToken as setApiToken } from '../api'

/**
 * Holds the JWT for the session. Unlike the web app (which keeps the token in
 * JS memory only and drops it on refresh), a mobile app is expected to stay
 * signed in across cold starts, so we persist the token in the platform
 * keychain / keystore via expo-secure-store.
 */

const TOKEN_KEY = 'cyberasm.jwt'

interface AuthState {
  token: string | null
  loading: boolean
  signIn: (token: string) => Promise<void>
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthState | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    ;(async () => {
      try {
        const saved = await SecureStore.getItemAsync(TOKEN_KEY)
        if (saved) {
          setApiToken(saved)
          setTokenState(saved)
        }
      } finally {
        setLoading(false)
      }
    })()
  }, [])

  const signIn = useCallback(async (t: string) => {
    setApiToken(t)
    setTokenState(t)
    await SecureStore.setItemAsync(TOKEN_KEY, t)
  }, [])

  const signOut = useCallback(async () => {
    setApiToken(null)
    setTokenState(null)
    await SecureStore.deleteItemAsync(TOKEN_KEY)
  }, [])

  return (
    <AuthContext.Provider value={{ token, loading, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
