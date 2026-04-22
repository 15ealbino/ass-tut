import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { hasToken } from './api'
import EditorPage from './pages/Editor'
import LoginPage from './pages/Login'
import RegisterPage from './pages/Register'

function RequireAuth({ children }: { children: JSX.Element }) {
  return hasToken() ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/" element={<RequireAuth><EditorPage /></RequireAuth>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
