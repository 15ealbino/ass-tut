import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import EditorPage from './pages/Editor'
import LoginPage from './pages/Login'
import RegisterPage from './pages/Register'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<EditorPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
