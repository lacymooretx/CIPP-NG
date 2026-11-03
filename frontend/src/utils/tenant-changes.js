// Wording for the What Changed page (Aspendora fork, Vikunja CIPP-58). Kept apart from the page so the rule that a
// failed read is never shown as "no changes" can be tested without rendering.

const CHANGE_SOURCES_EXCLUDED = ['Health']

export const windowLabel = (days) =>
  Number(days) === 1 ? 'the last 24 hours' : `the last ${days} days`

export const failedSources = (sources) =>
  (Array.isArray(sources) ? sources : []).filter(
    (source) => source.Status === 'CouldNotRead'
  )

// Read, but limited: nothing to compare with, or old data. Worth one line, not a warning.
export const limitedSources = (sources) =>
  (Array.isArray(sources) ? sources : []).filter(
    (source) => source.Status === 'NotComparable' || source.Status === 'Stale'
  )

// The one line a day with no changes gets. Returns null when there are changes, because the table says it all.
// Only sources actually read as OK are ever named as having no changes.
export const verdictLine = (record) => {
  const sources = Array.isArray(record?.Sources) ? record.Sources : []
  const changeSources = sources.filter(
    (source) => !CHANGE_SOURCES_EXCLUDED.includes(source.Name)
  )
  const when = windowLabel(record?.Days ?? 1)
  switch (record?.Verdict) {
    case 'Quiet':
      return { severity: 'success', text: `Nothing changed in ${when}.` }
    case 'Incomplete': {
      const clear = changeSources
        .filter((source) => source.Status === 'OK')
        .map((source) => source.Label)
      return {
        severity: 'info',
        text: clear.length
          ? `No changes found in ${when} for: ${clear.join(', ')}. The other sources could not confirm that.`
          : `No source could confirm whether anything changed in ${when}.`,
      }
    }
    case 'Unreadable':
      return {
        severity: 'error',
        text: 'Could not read any source, so nothing is known about this tenant.',
      }
    default:
      return null
  }
}

// A count for the info bar. A null count is not zero: the source either failed or had nothing to compare with.
export const countOrUnknown = (value, sources, name) => {
  if (value !== null && value !== undefined) return value
  const source = (Array.isArray(sources) ? sources : []).find(
    (item) => item.Name === name
  )
  return source && source.Status !== 'CouldNotRead'
    ? 'Not compared'
    : 'Could not read'
}
