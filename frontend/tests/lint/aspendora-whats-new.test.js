// Aspendora fork: keeps src/data/aspendora-whats-new.json valid so /cipp/whats-new always renders.
import { describe, expect, it } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import whatsNew from '../../src/data/aspendora-whats-new.json'

const pagesDir = path.resolve(__dirname, '../../src/pages')

const pageExists = (route) => {
  const base = path.join(pagesDir, route.split('?')[0])
  return ['.jsx', '.js', '/index.jsx', '/index.js'].some((ext) => fs.existsSync(base + ext))
}

describe('aspendora-whats-new.json', () => {
  const { areas, entries } = whatsNew

  it('has entries', () => {
    expect(Array.isArray(entries)).toBe(true)
    expect(entries.length).toBeGreaterThan(0)
  })

  it.each(entries.map((e) => [e.id ?? '(missing id)', e]))('%s is well formed', (_id, e) => {
    expect(e.id).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/)
    expect(e.date).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(Number.isNaN(new Date(`${e.date}T12:00:00Z`).getTime())).toBe(false)
    expect(typeof e.title).toBe('string')
    expect(e.title.trim().length).toBeGreaterThan(0)
    expect(areas).toContain(e.area)
    expect(typeof e.summary).toBe('string')
    expect(e.summary.trim().length).toBeGreaterThan(10)
    if (e.path !== undefined) {
      expect(e.path.startsWith('/')).toBe(true)
      expect(pageExists(e.path), `no page for ${e.path}`).toBe(true)
    }
  })

  it('has unique ids', () => {
    const ids = entries.map((e) => e.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('is newest first', () => {
    const dates = entries.map((e) => e.date)
    expect(dates).toEqual([...dates].sort().reverse())
  })
})
