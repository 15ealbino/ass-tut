import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { register, setToken } from '../api'
import styles from './Auth.module.css'

export default function RegisterPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await register(email, password)
      setToken(res.access_token)
      nav('/')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.container}>
      <div className={styles.card}>
        <h1 className={styles.title}>Assembly Tutorial</h1>
        <p className={styles.subtitle}>Create your account</p>
        <form onSubmit={submit} className={styles.form}>
          <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} required />
          <input type="password" placeholder="Password (min 8 chars)" value={password} onChange={e => setPassword(e.target.value)} minLength={8} maxLength={72} required />
          {error && <p className={styles.error}>{error}</p>}
          <button type="submit" className={styles.btn} disabled={loading}>
            {loading ? 'Creating account…' : 'Register'}
          </button>
        </form>
        <p className={styles.link}>Already have an account? <Link to="/login">Sign In</Link></p>
      </div>
    </div>
  )
}
