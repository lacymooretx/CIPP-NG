// Aspendora fork: the What's New page renders every entry and marks them seen.
import { fireEvent, render, screen } from '@testing-library/react'
import { vi } from 'vitest'

vi.mock('../../src/layouts/index', () => ({ Layout: ({ children }) => children }))

import Page from '../../src/pages/cipp/whats-new'
import whatsNew from '../../src/data/aspendora-whats-new.json'
import { WHATS_NEW_SEEN_KEY, hasUnseenWhatsNew, latestWhatsNewDate } from '../../src/utils/aspendora-whats-new'

describe('What\'s New (Aspendora) page', () => {
  beforeEach(() => window.localStorage.clear())

  it('renders all entries, flags them new on first visit, and records the visit', () => {
    expect(hasUnseenWhatsNew()).toBe(true)
    render(<Page />)
    for (const e of whatsNew.entries) expect(screen.getAllByText(e.title).length).toBeGreaterThan(0)
    expect(screen.getAllByText('New').length).toBe(whatsNew.entries.length)
    expect(window.localStorage.getItem(WHATS_NEW_SEEN_KEY)).toBe(latestWhatsNewDate())
    expect(hasUnseenWhatsNew()).toBe(false)
  })

  it('filters by search text', () => {
    render(<Page />)
    fireEvent.change(screen.getByPlaceholderText('Search features'), { target: { value: 'GDAP health' } })
    expect(screen.getByText('GDAP health monitor')).toBeTruthy()
    expect(screen.queryByText('Printers')).toBeNull()
  })
})
