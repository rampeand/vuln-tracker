function LoadingSpinner() {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="relative">
        <div className="w-12 h-12 border-4 border-gray-700 rounded-full"></div>
        <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin absolute top-0"></div>
      </div>
      <p className="mt-4 text-gray-400">Fetching vulnerabilities...</p>
      <p className="text-sm text-gray-500 mt-1">Aggregating from multiple sources</p>
    </div>
  )
}

export default LoadingSpinner
