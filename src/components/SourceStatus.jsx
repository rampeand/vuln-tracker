/**
 * SourceStatus Component
 *
 * Displays the refresh health and data freshness of each data source.
 * For each source it shows:
 *   - A colour-coded status indicator (green = ok, yellow = updating, red = error)
 *   - The ISO timestamp of the last successful refresh, formatted to local time
 *   - The number of records currently stored from that source
 *   - A per-source "Refresh" icon button for on-demand updates
 *   - Any error message from the last failed fetch
 *
 * Also shows:
 *   - A "Refresh All" button that triggers all four sources simultaneously
 *   - A countdown to the next scheduled hourly refresh
 *
 * Props:
 *   sourceStatus  {object}  Map of source name → { last_updated, status, count, error_message }
 *   nextRefresh   {string}  ISO datetime string of the next scheduled APScheduler run
 *   onRefresh     {function(source)} Callback; pass null/undefined to refresh all sources
 */
function SourceStatus({ sourceStatus, nextRefresh, onRefresh }) {
  // Canonical source names — must match SOURCE_NAMES in backend/main.py
  const sources = ['NVD', 'GitHub Advisory', 'CISA KEV', 'CCCS']

  /**
   * Returns a Tailwind text-colour class for a given status string.
   * Used to colour the status label text.
   */
  const statusTextColor = (status) => {
    switch (status) {
      case 'ok':       return 'text-green-400'
      case 'error':    return 'text-red-400'
      case 'updating': return 'text-yellow-400'
      default:         return 'text-gray-400'   // 'pending' or unknown
    }
  }

  /**
   * Returns a Tailwind background class for the small status dot indicator.
   * The 'updating' dot animates with a pulse to draw attention.
   */
  const statusDotClass = (status) => {
    switch (status) {
      case 'ok':       return 'bg-green-400'
      case 'error':    return 'bg-red-400'
      case 'updating': return 'bg-yellow-400 animate-pulse'
      default:         return 'bg-gray-500'
    }
  }

  /**
   * Format an ISO 8601 datetime string for display in the user's local timezone.
   * Returns "Never" when the timestamp is null/undefined (source not yet fetched).
   */
  const formatTimestamp = (ts) => {
    if (!ts) return 'Never'
    return new Date(ts).toLocaleString()
  }

  /**
   * Convert the next scheduled refresh ISO timestamp to a human-friendly countdown.
   * Returns strings like "< 1 min", "23 min", "1h" depending on distance.
   * Returns null if the timestamp is missing (scheduler not yet started).
   */
  const formatCountdown = (ts) => {
    if (!ts) return null
    const diffMs = new Date(ts) - new Date()
    const diffMin = Math.round(diffMs / 60000)
    if (diffMin < 1) return '< 1 min'
    if (diffMin < 60) return `${diffMin} min`
    return `${Math.round(diffMin / 60)}h`
  }

  // True if any source is currently being refreshed — disables the "Refresh All" button
  const anyUpdating = sources.some(
    (s) => sourceStatus?.[s]?.status === 'updating'
  )

  return (
    <div className="bg-gray-800 rounded-lg p-4 mb-6 border border-gray-700">
      {/* Panel header row */}
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
          Data Source Status
        </h3>

        <div className="flex items-center gap-3">
          {/* Next scheduled refresh countdown */}
          {nextRefresh && (
            <span className="text-xs text-gray-500">
              Next auto-refresh in {formatCountdown(nextRefresh)}
            </span>
          )}

          {/* Global "Refresh All" button */}
          <button
            onClick={() => onRefresh(null)}
            disabled={anyUpdating}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white text-xs rounded font-medium transition-colors flex items-center gap-1.5"
            title="Refresh all data sources now"
          >
            {/* Spinner icon — rotates when any source is updating */}
            <svg
              className={`w-3 h-3 ${anyUpdating ? 'animate-spin' : ''}`}
              fill="none" stroke="currentColor" viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            Refresh All
          </button>
        </div>
      </div>

      {/* Per-source cards grid — 1 column on mobile, 2 on md, 4 on lg+ screens */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {sources.map((source) => {
          const info = sourceStatus?.[source] || {}
          const isUpdating = info.status === 'updating'

          return (
            <div
              key={source}
              className="bg-gray-700/50 rounded-lg p-3 flex flex-col gap-1.5 border border-gray-600/50"
            >
              {/* Source name row with status dot and per-source refresh button */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {/* Colour-coded status indicator dot */}
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${statusDotClass(info.status)}`} />
                  <span className="text-sm font-semibold text-white">{source}</span>
                </div>

                {/* Per-source refresh icon button */}
                <button
                  onClick={() => onRefresh(source)}
                  disabled={isUpdating}
                  className="p-1 rounded text-gray-400 hover:text-white hover:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                  title={`Refresh ${source} now`}
                  aria-label={`Refresh ${source}`}
                >
                  <svg
                    className={`w-3.5 h-3.5 ${isUpdating ? 'animate-spin' : ''}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                    />
                  </svg>
                </button>
              </div>

              {/* Status label + record count */}
              <div className="flex items-center gap-2 text-xs">
                <span className={`capitalize font-medium ${statusTextColor(info.status)}`}>
                  {isUpdating ? 'Updating...' : (info.status || 'pending')}
                </span>
                {info.count > 0 && (
                  <span className="text-gray-500">
                    · {info.count.toLocaleString()} records
                  </span>
                )}
              </div>

              {/* Last successful update timestamp */}
              <div className="text-xs text-gray-500">
                <span className="text-gray-600">Updated: </span>
                {formatTimestamp(info.last_updated)}
              </div>

              {/* Error message (only shown when status === 'error') */}
              {info.error_message && (
                <div
                  className="text-xs text-red-400 truncate mt-0.5"
                  title={info.error_message}
                >
                  ⚠ {info.error_message}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default SourceStatus
