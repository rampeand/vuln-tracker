function FilterBar({
  days,
  setDays,
  severityFilter,
  setSeverityFilter,
  sourceFilter,
  setSourceFilter,
  searchTerm,
  setSearchTerm,
  onSearch
}) {
  const daysOptions = [1, 2, 3, 7, 14, 30]
  const severityOptions = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const sourceOptions = ['', 'NVD', 'GitHub', 'CISA']

  return (
    <div className="bg-gray-800 rounded-lg p-4 mb-6 border border-gray-700">
      <div className="flex flex-col lg:flex-row gap-4">
        {/* Time Range */}
        <div className="flex-shrink-0">
          <label className="block text-xs font-medium text-gray-400 mb-1">Time Range</label>
          <div className="flex gap-1">
            {daysOptions.map((d) => (
              <button
                key={d}
                onClick={() => setDays(d)}
                className={`px-3 py-2 text-sm rounded transition-colors ${
                  days === d
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {d}d
              </button>
            ))}
          </div>
        </div>

        {/* Severity Filter */}
        <div className="flex-shrink-0">
          <label className="block text-xs font-medium text-gray-400 mb-1">Severity</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-gray-700 text-gray-200 rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="">All Severities</option>
            {severityOptions.slice(1).map((sev) => (
              <option key={sev} value={sev}>{sev}</option>
            ))}
          </select>
        </div>

        {/* Source Filter */}
        <div className="flex-shrink-0">
          <label className="block text-xs font-medium text-gray-400 mb-1">Source</label>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="bg-gray-700 text-gray-200 rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="">All Sources</option>
            {sourceOptions.slice(1).map((src) => (
              <option key={src} value={src}>{src}</option>
            ))}
          </select>
        </div>

        {/* Search */}
        <div className="flex-1">
          <label className="block text-xs font-medium text-gray-400 mb-1">Search</label>
          <form onSubmit={onSearch} className="flex gap-2">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search CVE ID, keywords..."
              className="flex-1 bg-gray-700 text-gray-200 rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none placeholder-gray-500"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm font-medium transition-colors"
            >
              Search
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}

export default FilterBar
