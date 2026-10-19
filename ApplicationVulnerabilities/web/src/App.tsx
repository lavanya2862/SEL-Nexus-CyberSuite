import { Route, Routes } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { Empty, PageHeader } from '@/components/kit'
import { RequireAuth } from '@/lib/auth'
import { Dashboard } from '@/pages/Dashboard'
import { NewScan } from '@/pages/NewScan'
import { Approvals } from '@/pages/Approvals'
import { FixesNeeded } from '@/pages/FixesNeeded'
import { Errors } from '@/pages/Errors'
import { AgentPage } from '@/pages/AgentPage'
import { Vulnerabilities } from '@/pages/Vulnerabilities'
import { Repositories } from '@/pages/Repositories'
import { Runs } from '@/pages/Runs'
import { RunDetail } from '@/pages/RunDetail'
import { Reports } from '@/pages/Reports'
import { HowItWorks } from '@/pages/HowItWorks'
import { SettingsPage } from '@/pages/Settings'

export default function App() {
  return (
    <Routes>
      {/* Everything needs a person signed in on the shared SEL Nexus CyberSuite sign-in page */}
      <Route element={<RequireAuth><AppShell /></RequireAuth>}>
        <Route index element={<Dashboard />} />
        <Route path="scan" element={<NewScan />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="fixes" element={<FixesNeeded />} />
        <Route path="errors" element={<Errors />} />
        <Route path="agents/:agent" element={<AgentPage />} />
        <Route path="vulnerabilities" element={<Vulnerabilities />} />
        <Route path="repositories" element={<Repositories />} />
        <Route path="runs" element={<Runs />} />
        <Route path="runs/:id/:tab?" element={<RunDetail />} />
        <Route path="reports" element={<Reports />} />
        <Route path="how" element={<HowItWorks />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<div className="flex flex-col gap-5"><PageHeader title="Page not found" description="This address does not exist. Use the menu on the left." /><Empty text="Nothing here." /></div>} />
      </Route>
    </Routes>
  )
}
