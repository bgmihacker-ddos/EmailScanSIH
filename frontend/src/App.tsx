import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { UserLayout } from './components/layout/UserLayout';
import { AdminLayout } from './components/layout/AdminLayout';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import Callback from './pages/Callback';
import Signup from './pages/Signup';
import { PrivacyPolicy, TermsOfService } from './pages/Legal';
import HomePage from './pages/HomePage';
import LiveThreat from './pages/LiveThreat';
import AnalyzeEmail from './pages/AnalyzeEmail';
import BatchAnalysis from './pages/BatchAnalysis';
import AnalysisResult from './pages/AnalysisResult';
import Threats from './pages/Threats';
import ThreatDetail from './pages/ThreatDetail';
import Indicators from './pages/Indicators';
import EmailHistory from './pages/EmailHistory';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Cases from './pages/Cases';
import CaseDetail from './pages/CaseDetail';
import { SimulateAttack } from './pages/SimulateAttack';
import { AuditLogs as UserAuditLogs } from './pages/AuditLogs';

import AdminOverview from './pages/admin/AdminOverview';
import Users from './pages/admin/Users';
import Scans from './pages/admin/Scans';
import ThreatIntelligence from './pages/admin/ThreatIntelligence';
import SystemHealth from './pages/admin/SystemHealth';
import AuditLogs from './pages/admin/AuditLogs';
import AdminSettings from './pages/admin/AdminSettings';

function ProtectedRoute({ children, adminOnly = false }: { children?: React.ReactElement, adminOnly?: boolean }) {
    const { isAuthenticated, user, loading } = useAuth();

    if (loading) return <div>Loading...</div>;
    if (!isAuthenticated) return <Navigate to="/login" replace />;
    if (adminOnly && user?.role !== 'admin') return <Navigate to="/dashboard" replace />;

    return children ? children : <Outlet />;
}

function RoleBasedSettings() {
    const { user, loading } = useAuth();
    if (loading) return <div>Loading...</div>;
    if (!user) return <Navigate to="/login" replace />;
    if (user.role === 'admin') return <AdminLayout><Settings /></AdminLayout>;
    return <UserLayout><Settings /></UserLayout>;
}

function AppContent() {
  return (
    <Router>
        <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/login" element={<Login />} />
            <Route path="/auth/callback" element={<Callback />} />
            <Route path="/signup" element={<Signup />} />
            <Route path="/policy" element={<PrivacyPolicy />} />
            <Route path="/service" element={<TermsOfService />} />

            <Route element={<ProtectedRoute />}>
                <Route element={<UserLayout children={<Outlet />} />}>
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/analyze" element={<AnalyzeEmail />} />
                    <Route path="/batch-analysis" element={<BatchAnalysis />} />
                    <Route path="/analysis/:id" element={<AnalysisResult />} />
                    <Route path="/live-threat" element={<LiveThreat />} />
                    <Route path="/threats" element={<Threats />} />
                    <Route path="/threats/:id" element={<ThreatDetail />} />
                    <Route path="/indicators" element={<Indicators />} />
                    <Route path="/history" element={<EmailHistory />} />
                    <Route path="/reports" element={<Reports />} />
                    <Route path="/cases" element={<Cases />} />
                    <Route path="/cases/:id" element={<CaseDetail />} />
                    <Route path="/simulate" element={<SimulateAttack />} />
                    <Route path="/audit-logs" element={<UserAuditLogs />} />
                </Route>

                <Route path="/settings" element={<RoleBasedSettings />} />

                <Route path="/admin/*" element={
                    <ProtectedRoute adminOnly>
                        <AdminLayout children={<Outlet />} />
                    </ProtectedRoute>
                }>
                    <Route path="" element={<AdminOverview />} />
                    <Route path="users" element={<Users />} />
                    <Route path="scans" element={<Scans />} />
                    <Route path="threat-intelligence" element={<ThreatIntelligence />} />
                    <Route path="system-health" element={<SystemHealth />} />
                    <Route path="audit-logs" element={<AuditLogs />} />
                    <Route path="settings" element={<AdminSettings />} />
                </Route>
            </Route>
        </Routes>
    </Router>
  );
}

function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <AppContent />
      </ToastProvider>
    </AuthProvider>
  );
}

export default App
