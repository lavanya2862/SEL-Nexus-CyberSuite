import { Route, Routes } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { ActivityLog } from '@/pages/ActivityLog'
import { ComingSoon, Home } from '@/pages/Home'
import { Reports } from '@/pages/Reports'
import { Respond } from '@/pages/Respond'
import { RespondCase } from '@/pages/RespondCase'
import { Runs } from '@/pages/Runs'
import { Hunting } from '@/pages/uc1/Hunting'
import { ThreatDetail } from '@/pages/uc1/ThreatDetail'
import { ThreatNews } from '@/pages/uc1/ThreatNews'
import { FixCentre } from '@/pages/uc3/FixCentre'
import { FixProgress } from '@/pages/uc3/FixProgress'
import { Vulnerabilities } from '@/pages/uc3/Vulnerabilities'
import { VulnDetail } from '@/pages/uc3/VulnDetail'
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
          <Route path="uc1/*" element={<GlassSoon title="Threats & hunting" />} />
          <Route path="uc3/*" element={<GlassSoon title="Vulnerability management" />} />
          <Route path="fixes" element={<GlassSoon title="Remediation" />} />
          <Route path="reports" element={<GlassSoon title="Reports" />} />
          <Route path="*" element={<GlassSoon title="Page not found" />} />
        </Route>
        <Route element={<RequireAuth><AppShell /></RequireAuth>}>
          <Route index element={<Home />} />
          <Route path="uc1/hunts" element={<Hunting />} />
          <Route path="uc1/threat/:id" element={<ThreatDetail />} />
          <Route path="uc1/:tab?" element={<ThreatNews />} />
          <Route path="uc3/vuln/:key" element={<VulnDetail />} />
          <Route path="uc3/:tab?" element={<Vulnerabilities />} />
          <Route path="fixes/progress" element={<FixProgress />} />
          <Route path="fixes/:tab?" element={<FixCentre />} />
          <Route path="reports" element={<Reports />} />
          <Route path="activity" element={<ActivityLog />} />
          <Route path="respond"element={<Respond />} />
          <Route path="respond/:id" element={<RespondCase />} />
          <Route path="runs/:uc?" element={<Runs />} />
          <Route path="*" element={<ComingSoon title="Page not found" phase="unknown address" />} />
        </Route>
      </Routes>
  )
}
