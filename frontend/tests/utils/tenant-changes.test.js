import { describe, expect, it } from 'vitest'
import {
  countOrUnknown,
  failedSources,
  limitedSources,
  verdictLine,
  windowLabel,
} from '../../src/utils/tenant-changes'

const source = (Name, Status, Label = Name) => ({ Name, Label, Status })

describe('What Changed wording', () => {
  it('says nothing changed only on a Quiet verdict', () => {
    expect(verdictLine({ Verdict: 'Quiet', Days: 1, Sources: [] })).toEqual({
      severity: 'success',
      text: 'Nothing changed in the last 24 hours.',
    })
  })

  it('never names an unread source as having no changes', () => {
    const line = verdictLine({
      Verdict: 'Incomplete',
      Days: 7,
      Sources: [
        source('Alerts', 'CouldNotRead'),
        source('Tests', 'NotComparable', 'Test results'),
        source('SecureScore', 'OK', 'Secure Score'),
        source('Health', 'OK', 'Data age'),
      ],
    })
    expect(line.severity).toBe('info')
    expect(line.text).toContain('the last 7 days for: Secure Score.')
    expect(line.text).not.toContain('Alerts')
    expect(line.text).not.toContain('Test results')
    expect(line.text).not.toContain('Data age')
  })

  it('does not claim anything when no change source read cleanly', () => {
    const line = verdictLine({
      Verdict: 'Incomplete',
      Days: 1,
      Sources: [source('Alerts', 'CouldNotRead')],
    })
    expect(line.text).toBe(
      'No source could confirm whether anything changed in the last 24 hours.'
    )
  })

  it('reports an unreadable tenant as an error', () => {
    expect(verdictLine({ Verdict: 'Unreadable', Sources: [] }).severity).toBe(
      'error'
    )
  })

  it('adds no line when there are changes', () => {
    expect(verdictLine({ Verdict: 'Changes', Sources: [] })).toBeNull()
  })

  it('shows a null count as could not read or not compared, and keeps a real zero', () => {
    const sources = [
      source('Alerts', 'CouldNotRead'),
      source('Tests', 'NotComparable'),
    ]
    expect(countOrUnknown(null, sources, 'Alerts')).toBe('Could not read')
    expect(countOrUnknown(undefined, sources, 'Missing')).toBe('Could not read')
    expect(countOrUnknown(null, sources, 'Tests')).toBe('Not compared')
    expect(countOrUnknown(0, sources, 'Alerts')).toBe(0)
  })

  it('sorts sources by what the page says about them', () => {
    const sources = [
      source('A', 'OK'),
      source('B', 'CouldNotRead'),
      source('C', 'Stale'),
      source('D', 'NotComparable'),
    ]
    expect(failedSources(sources).map((s) => s.Name)).toEqual(['B'])
    expect(limitedSources(sources).map((s) => s.Name)).toEqual(['C', 'D'])
    expect(failedSources(undefined)).toEqual([])
  })

  it('labels the window', () => {
    expect(windowLabel(1)).toBe('the last 24 hours')
    expect(windowLabel(7)).toBe('the last 7 days')
  })
})
