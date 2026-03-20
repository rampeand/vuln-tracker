/**
 * App — Root component for the Vulnerability Tracker SPA.
 *
 * Responsibilities:
 *   - Owns all application state (vulnerabilities, stats, source status, filters)
 *   - Fetches data from the FastAPI backend (/api/vulnerabilities, /api/stats,
 *     /api/sources/status)
 *   - Polls /api/sources/status every 15 seconds so the UI reflects background
 *     refresh progress without requiring a full page reload
 *   - Exposes onRefreshSource() callback passed down to SourceStatus for
 *     per-source and global on-demand refresh
 *   - Composes the page layout: Header → StatsPanel → SourceStatus →
 *     FilterBar → VulnerabilityCard list → Footer
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import VulnerabilityCard from './components/VulnerabilityCard'
import StatsPanel from './components/StatsPanel'
import FilterBar from './components/FilterBar'
import LoadingSpinner from './components/LoadingSpinner'
import SourceStatus from './components/SourceStatus'

// Resolve API base URL:
//   - Production (served by Nginx): use a relative path so requests go through
//     the /api/* proxy rule defined in nginx.conf
//   - Development (Vite dev server): fall back to VITE_API_URL env variable or
//     the default local backend port
const API_URL = import.meta.env.PROD
  ? ''
  : (import.meta.env.VITE_API_URL || 'http://localhost:8000')

function App() {
  // ── Vulnerability data state ──────────────────────────────────────────────
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // ── Source freshness state ────────────────────────────────────────────────
  // sourceStatus: { "NVD": { last_updated, status, count, error_message }, ... }
  const [sourceStatus, setSourceStatus] = useState({})
  // nextRefresh: ISO datetime string of the next APScheduler hourly run
  const [nextRefresh, setNextRefresh] = useState(null)

  // ── Filter / search state ─────────────────────────────────────────────────
  const [days, setDays] = useState(2)
  const [severityFilter, setSeverityFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  // ── Detail overlay ────────────────────────────────────────────────────────
  // selectedVuln: the currently expanded VulnerabilityCard, or null if none
  const [selectedVuln, setSelectedVuln] = useState(null)

  // Ref used to cancel the source-status polling interval on unmount
  const statusPollRef = useRef(null)

  // ── Colour helpers ────────────────────────────────────────────────────────
  /**
   * Map a severity string to a Tailwind background-colour class.
   * Used by StatsPanel dots and VulnerabilityCard severity badges.
   */
  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: 'bg-red-600',
      HIGH:     'bg-orange-500',
      MEDIUM:   'bg-yellow-500',
      LOW:      'bg-blue-500',
      UNKNOWN:  'bg-gray-500'
    }
    return colors[severity] || colors.UNKNOWN
  }

  // ── Data fetching ─────────────────────────────────────────────────────────

  /**
   * Fetch the vulnerability list and stats in parallel.
   * Called on mount, on filter changes, and when the user clicks Refresh.
   */
  const fetchVulnerabilities = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      // Build query string from current filter state
      const params = new URLSearchParams({ days: days.toString() })
      if (severityFilter) params.append('severity', severityFilter)
      if (sourceFilter)   params.append('source',   sourceFilter)
      if (searchTerm)     params.append('search',   searchTerm)

      // Fire both requests concurrently to minimise total wait time
      const [vulnResponse, statsResponse] = await Promise.all([
        fetch(`${API_URL}/api/vulnerabilities?${params}`),
        fetch(`${API_URL}/api/stats?days=${days}`)
      ])

      if (!vulnResponse.ok || !statsResponse.ok) {
        throw new Error('Failed to fetch vulnerability data')
      }

      const vulnData  = await vulnResponse.json()
      const statsData = await statsResponse.json()

      setVulnerabilities(vulnData.vulnerabilities)
      setStats(statsData)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [days, severityFilter, sourceFilter, searchTerm])

  /**
   * Fetch per-source status metadata from GET /api/sources/status.
   * Called on mount and then polled every 15 seconds so the SourceStatus
   * panel reflects in-progress refreshes without a manual page reload.
   */
  const fetchSourceStatus = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/sources/status`)
      if (response.ok) {
        const data = await response.json()
        setSourceStatus(data.sources || {})
        setNextRefresh(data.next_refresh || null)
      }
    } catch {
      // Non-critical — silently ignore network errors in the status poll
    }
  }, [])

  /**
   * Trigger an on-demand refresh for a specific source, or all sources if
   * source is null.  After posting the request, immediately re-fetch source
   * status so the UI shows "updating" straight away.
   *
   * @param {string|null} source  Canonical source name, or null for all
   */
  const handleRefreshSource = useCallback(async (source) => {
    try {
      await fetch(`${API_URL}/api/sources/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Empty body triggers a full refresh; { source } targets one source
        body: JSON.stringify(source ? { source } : {})
      })
      // Pull fresh status immediately so the "updating" indicator appears
      await fetchSourceStatus()
    } catch (err) {
      console.error('Failed to trigger refresh:', err)
    }
  }, [fetchSourceStatus])

  // ── Effects ───────────────────────────────────────────────────────────────

  // Re-fetch vulnerabilities whenever the filter state changes
  useEffect(() => {
    fetchVulnerabilities()
  }, [days, severityFilter, sourceFilter]) // eslint-disable-line react-hooks/exhaustive-deps
  // Note: searchTerm is intentionally excluded — search is submitted explicitly
  // via the form onSubmit so it only fires when the user presses Enter / Search.

  // Fetch source status on mount, then poll every 15 seconds.
  // The interval is cleared on component unmount to prevent memory leaks.
  useEffect(() => {
    fetchSourceStatus()
    statusPollRef.current = setInterval(fetchSourceStatus, 15000)
    return () => clearInterval(statusPollRef.current)
  }, [fetchSourceStatus])

  // ── Event handlers ────────────────────────────────────────────────────────

  /** Handle the search form submit — triggers a new fetch with current searchTerm */
  const handleSearch = (e) => {
    e.preventDefault()
    fetchVulnerabilities()
  }

  /**
   * Handle the header Refresh button click.
   * Refreshes both the vulnerability list and source status simultaneously.
   */
  const handleFullRefresh = () => {
    fetchVulnerabilities()
    fetchSourceStatus()
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">

      {/* ── Sticky header ─────────────────────────────────────────────────── */}
      <header className="bg-gray-800 border-b border-gray-700 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">

            {/* Brand / title */}
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-red-600 rounded-lg flex items-center justify-center">
                {/* Warning triangle icon */}
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold">Vulnerability Tracker</h1>
                <p className="text-sm text-gray-400">Real-time security intelligence</p>
              </div>
            </div>

            {/* Refresh button — refreshes vuln list and source status */}
            <div className="flex items-center gap-4">
              <button
                onClick={handleFullRefresh}
                disabled={loading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed rounded-lg font-medium transition-colors flex items-center gap-2"
              >
                <svg
                  className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`}
                  fill="none" stroke="currentColor" viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                  />
                </svg>
                Refresh
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* ── Main content ──────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 py-6">

        {/* Aggregate severity / source counts */}
        {stats && <StatsPanel stats={stats} getSeverityColor={getSeverityColor} />}

        {/* Per-source last-update timestamps and on-demand refresh buttons */}
        <SourceStatus
          sourceStatus={sourceStatus}
          nextRefresh={nextRefresh}
          onRefresh={handleRefreshSource}
        />

        {/* Filters: time range, severity, source, text search */}
        <FilterBar
          days={days}
          setDays={setDays}
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          sourceFilter={sourceFilter}
          setSourceFilter={setSourceFilter}
          searchTerm={searchTerm}
          setSearchTerm={setSearchTerm}
          onSearch={handleSearch}
        />

        {/* Error banner with retry link */}
        {error && (
          <div className="bg-red-900/50 border border-red-700 rounded-lg p-4 mb-6">
            <div className="flex items-center gap-3">
              <svg className="w-5 h-5 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <span className="text-red-200">{error}</span>
              <button
                onClick={fetchVulnerabilities}
                className="ml-auto text-red-400 hover:text-red-300 underline flex-shrink-0"
              >
                Retry
              </button>
            </div>
          </div>
        )}

        {/* Loading spinner while data is in-flight */}
        {loading && <LoadingSpinner />}

        {/* Vulnerability list — hidden while loading to avoid flicker */}
        {!loading && !error && (
          <div className="space-y-4">

            {/* Result count header */}
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">
                {vulnerabilities.length} Vulnerabilities Found
              </h2>
              <span className="text-sm text-gray-400">
                Last {days} day{days !== 1 ? 's' : ''}
              </span>
            </div>

            {/* Empty state */}
            {vulnerabilities.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <svg className="w-16 h-16 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
                <p>No vulnerabilities found matching your criteria</p>
              </div>
            ) : (
              /* Vulnerability cards — each expands on click to show full details */
              <div className="grid gap-4">
                {vulnerabilities.map((vuln) => (
                  <VulnerabilityCard
                    key={vuln.id}
                    vulnerability={vuln}
                    getSeverityColor={getSeverityColor}
                    isSelected={selectedVuln?.id === vuln.id}
                    onSelect={() => setSelectedVuln(
                      selectedVuln?.id === vuln.id ? null : vuln
                    )}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {/* ── Footer ────────────────────────────────────────────────────────── */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-12 py-6">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>Data sources: NVD, GitHub Security Advisories, CISA KEV, CCCS</p>
          <p className="mt-1">Database updated hourly · on-demand refresh available above</p>
        </div>
      </footer>
    </div>
  )
}

export default App
