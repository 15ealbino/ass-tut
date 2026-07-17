import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { setToken as setApiToken } from '../api'
import { getItem, setItem, deleteItem } from '../storage'

/**
 * Holds the JWT for the session. Unlike the browser build of the original web
 * app (which keeps the token in JS memory only and drops it on refresh), the
 * app persists the token so a session survives cold starts — in the platform
 * keychain/keystore on native, and in localStorage on the web build (see
 * ../storage).
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
        const saved = await getItem(TOKEN_KEY)
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
    await setItem(TOKEN_KEY, t)
  }, [])

  const signOut = useCallback(async () => {
    setApiToken(null)
    setTokenState(null)
    await deleteItem(TOKEN_KEY)
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
