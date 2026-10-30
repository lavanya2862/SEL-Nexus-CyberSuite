import { createContext, useContext, useState, type ReactNode } from 'react'

export type OpcoFilter = 'all' | string
export type WorkTab = 'fixes' | 'threats' | 'devices'

interface FilterState {
  opco: OpcoFilter
  setOpco: (o: OpcoFilter) => void
  includeTests: boolean
  setIncludeTests: (v: boolean) => void
  workTab: WorkTab
  setWorkTab: (t: WorkTab) => void
}

const FilterContext = createContext<FilterState>({
  opco: 'all', setOpco: () => {}, includeTests: false, setIncludeTests: () => {}, workTab: 'fixes', setWorkTab: () => {},
})

/** Page-wide filters (OpCo, lab tests) and the active tab of the main work panel, shared by the shell and pages. */
export function FilterProvider({ children }: { children: ReactNode }) {
  const [opco, setOpco] = useState<OpcoFilter>('all')
  // lab tests (harmless activity made on purpose to prove the hunts work) are hidden unless switched on in Filters
  const [includeTests, setIncludeTests] = useState(false)
  const [workTab, setWorkTab] = useState<WorkTab>('fixes')
  return (
    <FilterContext.Provider value={{ opco, setOpco, includeTests, setIncludeTests, workTab, setWorkTab }}>
      {children}
    </FilterContext.Provider>
  )
}

export const useFilters = () => useContext(FilterContext)
