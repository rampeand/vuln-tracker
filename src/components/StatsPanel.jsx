function StatsPanel({ stats, getSeverityColor }) {
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

  return (
    <div className="mb-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
        {/* Total */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="text-3xl font-bold text-white">{stats.total}</div>
          <div className="text-sm text-gray-400">Total Vulnerabilities</div>
        </div>

        {/* Severity Breakdown */}
        {severityOrder.slice(0, 4).map((sev) => (
          <div
            key={sev}
            className="bg-gray-800 rounded-lg p-4 border border-gray-700"
          >
            <div className="flex items-center gap-2 mb-1">
              <div className={`w-3 h-3 rounded-full ${getSeverityColor(sev)}`}></div>
              <span className="text-xs font-medium text-gray-400 uppercase">{sev}</span>
            </div>
            <div className="text-2xl font-bold text-white">
              {stats.by_severity[sev] || 0}
            </div>
          </div>
        ))}
      </div>

      {/* Source Breakdown */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h3 className="text-sm font-medium text-gray-400 mb-3">By Source</h3>
        <div className="flex flex-wrap gap-4">
          {Object.entries(stats.by_source).map(([source, count]) => (
            <div key={source} className="flex items-center gap-2">
              <span className="text-white font-semibold">{count}</span>
              <span className="text-gray-400">{source}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default StatsPanel
