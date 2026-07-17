import React, { useEffect, useState } from 'react'
import {
  View,
  Text,
  TextInput,
  Pressable,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  ActivityIndicator,
  ScrollView,
} from 'react-native'
import type { NativeStackScreenProps } from '@react-navigation/native-stack'
import { login, setToken } from '../api'
import { useAuth } from '../context/AuthContext'
import { getApiBaseUrl, setApiBaseUrl, defaultApiBaseUrl } from '../config'
import { colors, mono } from '../theme'
import type { RootStackParamList } from '../../App'

type Props = NativeStackScreenProps<RootStackParamList, 'Login'>

export default function LoginScreen({ navigation }: Props) {
  const { signIn } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const [showServer, setShowServer] = useState(false)
  const [server, setServer] = useState('')

  useEffect(() => {
    getApiBaseUrl().then(setServer)
  }, [])

  async function submit() {
    setLoading(true)
    setError('')
    try {
      if (showServer) await setApiBaseUrl(server)
      const res = await login(email.trim(), password)
      setToken(res.access_token)
      await signIn(res.access_token)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <KeyboardAvoidingView
      style={styles.flex}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
    >
      <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
        <View style={styles.card}>
          <Text style={styles.brand}>
            <Text style={{ color: colors.green }}>CYBER</Text>
            <Text style={{ color: colors.textDim }}>//</Text>
            <Text style={{ color: colors.cyan }}>ASM</Text>
          </Text>
          <Text style={styles.subtitle}>Sign in to start learning</Text>

          <TextInput
            style={styles.input}
            placeholder="Email"
            placeholderTextColor={colors.textMuted}
            value={email}
            onChangeText={setEmail}
            autoCapitalize="none"
            keyboardType="email-address"
            autoCorrect={false}
          />
          <TextInput
            style={styles.input}
            placeholder="Password"
            placeholderTextColor={colors.textMuted}
            value={password}
            onChangeText={setPassword}
            secureTextEntry
          />

          {error ? <Text style={styles.error}>{error}</Text> : null}

          <Pressable
            style={[styles.btn, loading && styles.btnDisabled]}
            onPress={submit}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color={colors.green} />
            ) : (
              <Text style={styles.btnText}>SIGN IN</Text>
            )}
          </Pressable>

          <Pressable onPress={() => navigation.navigate('Register')}>
            <Text style={styles.link}>
              Don't have an account? <Text style={styles.linkStrong}>Register</Text>
            </Text>
          </Pressable>

          <Pressable onPress={() => setShowServer((s) => !s)} style={styles.serverToggle}>
            <Text style={styles.serverToggleText}>
              {showServer ? '▾ SERVER' : '▸ SERVER'}
            </Text>
          </Pressable>
          {showServer ? (
            <View style={{ width: '100%' }}>
              <TextInput
                style={[styles.input, styles.serverInput]}
                placeholder={defaultApiBaseUrl()}
                placeholderTextColor={colors.textMuted}
                value={server}
                onChangeText={setServer}
                autoCapitalize="none"
                autoCorrect={false}
              />
              <Text style={styles.hint}>
                Backend API base URL. Default: {defaultApiBaseUrl()}
              </Text>
            </View>
          ) : null}
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  )
}

export const authStyles = StyleSheet.create({
  flex: { flex: 1, backgroundColor: colors.bgBase },
  container: {
    flexGrow: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
  },
  card: {
    width: '100%',
    maxWidth: 400,
    backgroundColor: colors.bgPanel,
    borderWidth: 1,
    borderColor: colors.borderDim,
    borderRadius: 4,
    padding: 24,
    gap: 14,
    alignItems: 'center',
  },
  brand: {
    fontFamily: mono,
    fontSize: 26,
    fontWeight: '700',
    letterSpacing: 3,
  },
  subtitle: {
    fontFamily: mono,
    fontSize: 12,
    color: colors.textDim,
    marginBottom: 6,
  },
  input: {
    width: '100%',
    backgroundColor: colors.bgBase,
    borderWidth: 1,
    borderColor: colors.borderDim,
    borderRadius: 2,
    color: colors.textPrimary,
    paddingVertical: 12,
    paddingHorizontal: 14,
    fontFamily: mono,
    fontSize: 14,
  },
  serverInput: { fontSize: 12 },
  error: {
    width: '100%',
    color: colors.red,
    fontFamily: mono,
    fontSize: 12,
  },
  btn: {
    width: '100%',
    borderWidth: 1,
    borderColor: colors.green,
    backgroundColor: colors.greenFaint,
    borderRadius: 2,
    paddingVertical: 13,
    alignItems: 'center',
  },
  btnDisabled: { opacity: 0.4 },
  btnText: {
    color: colors.green,
    fontFamily: mono,
    fontWeight: '700',
    fontSize: 13,
    letterSpacing: 1.5,
  },
  link: {
    fontFamily: mono,
    fontSize: 12,
    color: colors.textDim,
    marginTop: 4,
  },
  linkStrong: { color: colors.cyan },
  serverToggle: { marginTop: 4 },
  serverToggleText: {
    fontFamily: mono,
    fontSize: 11,
    color: colors.textMuted,
    letterSpacing: 1,
  },
  hint: {
    fontFamily: mono,
    fontSize: 10,
    color: colors.textMuted,
    marginTop: 6,
  },
})

// LoginScreen consumes authStyles under the local name `styles`.
const styles = authStyles
