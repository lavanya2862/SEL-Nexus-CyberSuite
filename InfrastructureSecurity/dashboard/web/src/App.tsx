import { Route, Routes } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { ActivityLog } from '@/pages/ActivityLog'
import { ComingSoon, Home } from '@/pages/Home'
import { Reports } from '@/pages/Reports'
import { Respond } from '@/agents/alert-triage/Respond'
import { RespondCase } from '@/agents/alert-triage/RespondCase'
import { Runs } from '@/pages/Runs'
import { Hunting } from '@/agents/attack-detection/Hunting'
import { ThreatDetail } from '@/agents/threat-intel/ThreatDetail'
import { ThreatNews } from '@/agents/threat-intel/ThreatNews'
import { FixCentre } from '@/agents/fixes/FixCentre'
import { FixProgress } from '@/agents/fixes/FixProgress'
import { Vulnerabilities } from '@/agents/vulnerability/Vulnerabilities'
import { VulnDetail } from '@/agents/vulnerability/VulnDetail'
import { GlassHome, GlassSoon } from '@/glass/GlassHome'
import { GlassShell } from '@/glass/GlassShell'
import { LocalSignIn, RequireAuth } from '@/lib/auth'
import { Login } from '@/pages/auth/Login'
import { Signup } from '@/pages/auth/Signup'

export default function App() {
  return (
      <Routes>
        {/* Sign-in pages: the only screens open without an account (the shared CyberSuite sign-in page when set) */}
        <Route path="login" element={<LocalSignIn><Login /></LocalSignIn>} />
        <Route path="signup" element={<LocalSignIn><Signup /></LocalSignIn>} />
        {/* Preview: "Ember Glass" design at its own address; the classic design below is unchanged */}
        <Route path="glass" element={<RequireAuth><GlassShell /></RequireAuth>}>
          <Route index element={<GlassHome />} />
          <Route path="threat-intel/*" element={<GlassSoon title="Threats" />} />
          <Route path="vulnerabilities/*" element={<GlassSoon title="Vulnerabilities" />} />
          <Route path="fixes" element={<GlassSoon title="Remediation" />} />
          <Route path="reports" element={<GlassSoon title="Reports" />} />
          <Route path="*" element={<GlassSoon title="Page not found" />} />
        </Route>
        <Route element={<RequireAuth><AppShell /></RequireAuth>}>
          <Route index element={<Home />} />
          <Route path="attack-detection" element={<Hunting />} />
          <Route path="threat-intel/threat/:id" element={<ThreatDetail />} />
          <Route path="threat-intel/:tab?" element={<ThreatNews />} />
          <Route path="vulnerabilities/vuln/:key" element={<VulnDetail />} />
          <Route path="vulnerabilities/:tab?" element={<Vulnerabilities />} />
          <Route path="fixes/progress" element={<FixProgress />} />
          <Route path="fixes/:tab?" element={<FixCentre />} />
          <Route path="reports" element={<Reports />} />
          <Route path="activity" element={<ActivityLog />} />
          <Route path="alert-triage"element={<Respond />} />
          <Route path="alert-triage/:id" element={<RespondCase />} />
          <Route path="runs/:uc?" element={<Runs />} />
          <Route path="*" element={<ComingSoon title="Page not found" phase="unknown address" />} />
        </Route>
      </Routes>
  )
}
