// CodeGuard Dashboard — with real API integration
// Reads VITE_API_URL from environment (set in Vercel dashboard or .env)
// Falls back to mock analysis when backend is unavailable

const API_URL = import.meta.env.VITE_API_URL || ''

// ── Real API client ──────────────────────────────────────────────────────────
async function scanViaAPI(code, filename, repoUrl, isRepo) {
  try {
    if (isRepo) {
      const res = await fetch(`${API_URL}/scan/repo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: repoUrl, branch: 'main' })
      })
      if (!res.ok) throw new Error('API error')
      const { scan_id } = await res.json()
      return scan_id
    } else {
      const res = await fetch(`${API_URL}/scan/code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, filename })
      })
      if (!res.ok) throw new Error('API error')
      const { scan_id } = await res.json()
      return scan_id
    }
  } catch (e) {
    console.warn('API unavailable — using local analysis', e)
    return null
  }
}

async function pollScan(scan_id, onProgress) {
  for (let i = 0; i < 60; i++) {
    await new Promise(r => setTimeout(r, 1000))
    try {
      const res = await fetch(`${API_URL}/scan/${scan_id}`)
      const data = await res.json()
      onProgress(data.progress || 0)
      if (data.status === 'complete' || data.status === 'error') return data
    } catch (e) {
      continue
    }
  }
  throw new Error('Scan timed out')
}

// Export API functions for use in the main app
export { scanViaAPI, pollScan, API_URL }

// Re-export the full App component from the main dashboard file
export { default } from './Dashboard.jsx'
