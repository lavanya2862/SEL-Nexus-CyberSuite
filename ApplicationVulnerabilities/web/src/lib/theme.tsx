import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

export type Theme = 'light' | 'dark'

const ThemeContext = createContext<{ theme: Theme; setTheme: (t: Theme) => void; toggle: () => void }>({
  theme: 'dark', setTheme: () => {}, toggle: () => {},
})

// New key with the SEL Nexus CyberSuite rename: the old one stored 'light' for everyone, so dark would never show as the default.
export const THEME_KEY = 'nexus-theme'

function initialTheme(): Theme {
  const forced = new URLSearchParams(window.location.search).get('theme') // ?theme=dark for demos / screenshots
  if (forced === 'light' || forced === 'dark') return forced
  try {
    const saved = localStorage.getItem(THEME_KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* storage blocked: use the default */
  }
  return 'dark' // slate-navy dot field by default; light is one click away
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme)
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem(THEME_KEY, theme)
    } catch {
      /* not essential */
    }
  }, [theme])
  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggle: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')) }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)

// Chart palette: one validated categorical order for both modes (dataviz validator, 2026-10-05):
// signal orange, sky, teal, violet, amber, rose. Colour follows the entity; text never wears series colours.
export const chartTokens = {
  light: {
    surface: '#ffffff', ink: '#081030', ink2: '#3a4366', muted: '#636b8c', grid: '#e6e9f0', axis: '#ccd4df',
    series: ['#1d5cff', '#16a34a', '#d97706', '#9333ea', '#ea580c', '#0891b2', '#e11d48', '#db2777'],
    severity: { Critical: '#b8461a', High: '#f0763c', Medium: '#f6ad86', Low: '#f9d6c3', Unrated: '#ccd4df' },
    seq: ['#c7d7ff', '#7aa2ff', '#4f5ff0', '#8b3fe0', '#c42a7c'], // blue → violet → magenta, light = low, deep = high
  },
  // Ramps run the same way as in light mode (pale = low, deep = high / Critical), so a colour means the same thing in
  // both themes. The deepest step is lifted just enough to stay visible on the dark card (≥ 2.2:1, Critical ≥ 3.8:1).
  dark: {
    surface: '#0e1424', ink: '#eef2fb', ink2: '#bcc6dd', muted: '#8792b0', grid: '#1b2540', axis: '#2c3857',
    series: ['#3b74ff', '#22c55e', '#facc15', '#a855f7', '#f97316', '#06b6d4', '#f43f5e', '#ec4899'],
    severity: { Critical: '#e2581f', High: '#f2884f', Medium: '#f7b48f', Low: '#fbd9c6', Unrated: '#64748b' },
    seq: ['#a9c8ff', '#5b8cff', '#5e5cf2', '#9b3fe6', '#d9348f'], // blue → violet → magenta, light = low, deep = high
  },
} as const

export type ChartTokens = (typeof chartTokens)['light'] | (typeof chartTokens)['dark']

/** Label colour for text on a coloured fill: whichever of near-black / white reads better. */
export function inkOn(fill: string) {
  const lum = (hex: string) => {
    const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
      .map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b
  }
  const l = lum(fill)
  return (l + 0.05) / (lum('#0b1120') + 0.05) >= 1.05 / (l + 0.05) ? '#0b1120' : '#ffffff'
}

// Status colours are reserved for state and always ship with an icon + label.
export const statusColor = { good: '#0ca30c', warning: '#fab219', serious: '#ec835a', critical: '#d03b3b' } as const
