/**
 * StatsPanel Component
 *
 * Displays aggregate statistics for the current vulnerability dataset.
 * Shows:
 *   - Total vulnerability count
 *   - Count per severity level (CRITICAL, HIGH, MEDIUM, LOW) with colour dots
 *   - Count per data source (NVD, GitHub Advisory, CISA KEV)
 *
 * Props:
 *   stats           {object}  API response from GET /api/stats
 *     .total          {number}
 *     .by_severity    {object}  { CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN }
 *     .by_source      {object}  { "NVD": n, "GitHub Advisory": n, "CISA KEV": n }
 *   getSeverityColor {function(severity)} Returns a Tailwind bg-* class
 */
function StatsPanel({ stats, getSeverityColor }) {
  // Ordered list of severity levels to display (UNKNOWN intentionally omitted from cards)
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

  return (
    <div className="mb-6">

      {/* ── Top row: total + per-severity breakdown ────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">

        {/* Total vulnerability count */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="text-3xl font-bold text-white">{stats.total}</div>
          <div className="text-sm text-gray-400">Total Vulnerabilities</div>
        </div>

        {/* One card per severity level */}
        {severityOrder.map((sev) => (
          <div
            key={sev}
            className="bg-gray-800 rounded-lg p-4 border border-gray-700"
          >
            {/* Severity label with colour indicator */}
            <div className="flex items-center gap-2 mb-1">
              <div className={`w-3 h-3 rounded-full ${getSeverityColor(sev)}`} />
              <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">
                {sev}
              </span>
            </div>
            {/* Count — shows 0 when no vulnerabilities at this level */}
            <div className="text-2xl font-bold text-white">
              {stats.by_severity[sev] || 0}
            </div>
          </div>
        ))}
      </div>

      {/* ── Bottom row: per-source breakdown ──────────────────────────────── */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h3 className="text-sm font-medium text-gray-400 mb-3 uppercase tracking-wide">
          By Source
        </h3>
        <div className="flex flex-wrap gap-6">
          {Object.entries(stats.by_source).map(([source, count]) => (
            <div key={source} className="flex items-center gap-2">
              <span className="text-xl font-bold text-white">{count}</span>
              <span className="text-gray-400 text-sm">{source}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default StatsPanel
