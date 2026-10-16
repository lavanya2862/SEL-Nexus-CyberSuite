import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TooltipProvider } from '@/components/ui/tooltip'
import { AuthProvider } from '@/lib/auth'
import { DeviceNames } from '@/lib/deviceNames'
import { FilterProvider } from '@/lib/filters'
import { RunProvider } from '@/lib/runs'
import { ThemeProvider } from '@/lib/theme'
import './index.css'
import App from './App.tsx'

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } } })

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
        <DeviceNames />
        <TooltipProvider delayDuration={200}>
          <FilterProvider>
            <RunProvider>
              <App />
            </RunProvider>
          </FilterProvider>
        </TooltipProvider>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
    </BrowserRouter>
  </StrictMode>,
)
