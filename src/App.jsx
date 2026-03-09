import { useState, useEffect } from 'react'
import VulnerabilityCard from './components/VulnerabilityCard'
import StatsPanel from './components/StatsPanel'
import FilterBar from './components/FilterBar'
import LoadingSpinner from './components/LoadingSpinner'

const API_URL = import.meta.env.PROD ? '' : (import.meta.env.VITE_API_URL || 'http://localhost:8000')

function App() {
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [days, setDays] = useState(2)
  const [severityFilter, setSeverityFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedVuln, setSelectedVuln] = useState(null)

  const fetchVulnerabilities = async () => {
    setLoading(true)
    setError(null)

    try {
      const params = new URLSearchParams({ days: days.toString() })
      if (severityFilter) params.append('severity', severityFilter)
      if (sourceFilter) params.append('source', sourceFilter)
      if (searchTerm) params.append('search', searchTerm)

      const [vulnResponse, statsResponse] = await Promise.all([
        fetch(`${API_URL}/api/vulnerabilities?${params}`),
        fetch(`${API_URL}/api/stats?days=${days}`)
      ])

      if (!vulnResponse.ok || !statsResponse.ok) {
        throw new Error('Failed to fetch vulnerability data')
      }

      const vulnData = await vulnResponse.json()
      const statsData = await statsResponse.json()

      setVulnerabilities(vulnData.vulnerabilities)
      setStats(statsData)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchVulnerabilities()
  }, [days, severityFilter, sourceFilter])

  const handleSearch = (e) => {
    e.preventDefault()
    fetchVulnerabilities()
  }

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: 'bg-red-600',
      HIGH: 'bg-orange-500',
      MEDIUM: 'bg-yellow-500',
      LOW: 'bg-blue-500',
      UNKNOWN: 'bg-gray-500'
    }
    return colors[severity] || colors.UNKNOWN
  }

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-red-600 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold">Vulnerability Tracker</h1>
                <p className="text-sm text-gray-400">Real-time security intelligence</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <button
                onClick={fetchVulnerabilities}
                disabled={loading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed rounded-lg font-medium transition-colors flex items-center gap-2"
              >
                <svg className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Refresh
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6">
        {/* Stats Panel */}
        {stats && <StatsPanel stats={stats} getSeverityColor={getSeverityColor} />}

        {/* Filter Bar */}
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

        {/* Error State */}
        {error && (
          <div className="bg-red-900/50 border border-red-700 rounded-lg p-4 mb-6">
            <div className="flex items-center gap-3">
              <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-red-200">{error}</span>
              <button
                onClick={fetchVulnerabilities}
                className="ml-auto text-red-400 hover:text-red-300 underline"
              >
                Retry
              </button>
            </div>
          </div>
        )}

        {/* Loading State */}
        {loading && <LoadingSpinner />}

        {/* Vulnerabilities List */}
        {!loading && !error && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">
                {vulnerabilities.length} Vulnerabilities Found
              </h2>
              <span className="text-sm text-gray-400">
                Last {days} day{days !== 1 ? 's' : ''}
              </span>
            </div>

            {vulnerabilities.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <svg className="w-16 h-16 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <p>No vulnerabilities found matching your criteria</p>
              </div>
            ) : (
              <div className="grid gap-4">
                {vulnerabilities.map((vuln) => (
                  <VulnerabilityCard
                    key={vuln.id}
                    vulnerability={vuln}
                    getSeverityColor={getSeverityColor}
                    isSelected={selectedVuln?.id === vuln.id}
                    onSelect={() => setSelectedVuln(selectedVuln?.id === vuln.id ? null : vuln)}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-12 py-6">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>Data sources: NVD, GitHub Security Advisories, CISA KEV</p>
          <p className="mt-1">Updated every 15 minutes</p>
        </div>
      </footer>
    </div>
  )
}

export default App
