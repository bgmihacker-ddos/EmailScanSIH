import { ReactNode, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  ShieldCheck, Users, Mail, Globe, Activity, FileText,
  Settings, LogOut, LockKeyhole, ChevronLeft, ChevronRight,
  Bell, Server
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { SecurityEnvironmentBackground } from '../common/SecurityEnvironmentBackground';

export function AdminLayout({ children }: { children: ReactNode }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div className="flex h-screen overflow-hidden bg-deck font-sans text-ink antialiased">
      <SecurityEnvironmentBackground profile="admin" intensity="subtle" />

      <AdminSidebar collapsed={sidebarCollapsed} />

      <div className="relative z-10 flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-hairline bg-surface/90 px-4 backdrop-blur-md md:px-6">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="hidden h-8 w-8 items-center justify-center rounded-md border border-hairline text-ink-mute transition-colors hover:border-hairline-strong hover:text-ink md:flex"
              aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {sidebarCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
            </button>

            {/* Restricted-area identity */}
            <div className="flex items-center gap-2.5">
              <div className="relative">
                <Server size={14} className="text-ink-mute" />
                <span className="animate-live-dot absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-safe text-safe" />
              </div>
              <div className="hidden lg:block">
                <span className="font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-critical">Restricted area</span>
                <span className="ml-3 text-xs text-ink-mute">Administrator console</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button className="relative flex h-8 w-8 items-center justify-center rounded-md border border-hairline text-ink-mute transition-colors hover:border-hairline-strong hover:text-ink" aria-label="Alerts">
              <Bell size={15} />
              <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-critical" />
            </button>

            <div className="flex items-center gap-2 rounded-md border border-hairline bg-sunken px-2.5 py-2 font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-safe">
              <span className="animate-live-dot h-1.5 w-1.5 rounded-full bg-safe text-safe" />
              Platform online
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}

function AdminSidebar({ collapsed }: { collapsed: boolean }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className={`hidden md:flex flex-col border-r border-hairline bg-surface/60 transition-all duration-300 ${collapsed ? 'w-16' : 'w-60'}`}>
      <div className={`border-b border-hairline py-4 ${collapsed ? 'flex justify-center px-3' : 'px-4'}`}>
        <div className={`flex items-center gap-3 ${collapsed ? 'justify-center' : ''}`}>
          <div className="rounded-md border border-critical/30 bg-critical/10 p-2 text-critical">
            <LockKeyhole size={collapsed ? 18 : 18} />
          </div>
          {!collapsed && (
            <div>
              <h1 className="text-[13px] font-bold tracking-wide text-ink">EMAIL THREAT</h1>
              <p className="font-mono text-[9px] font-semibold tracking-[0.2em] text-critical">ADMINISTRATION</p>
            </div>
          )}
        </div>
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto p-3">
        <div>
          <p className="soc-label mb-2 px-3">{collapsed ? '' : 'Management'}</p>
          <div className="space-y-0.5">
            <AdminNavItem to="/admin" icon={ShieldCheck} name="Admin overview" collapsed={collapsed} end />
            <AdminNavItem to="/admin/users" icon={Users} name="Users" collapsed={collapsed} />
            <AdminNavItem to="/admin/scans" icon={Mail} name="Email scans" collapsed={collapsed} />
            <AdminNavItem to="/admin/threat-intelligence" icon={Globe} name="Threat intelligence" collapsed={collapsed} />
            <AdminNavItem to="/admin/system-health" icon={Activity} name="System health" collapsed={collapsed} />
            <AdminNavItem to="/admin/audit-logs" icon={FileText} name="Audit logs" collapsed={collapsed} />
          </div>
        </div>

        <div className="mt-4 border-t border-hairline pt-4">
          <p className="soc-label mb-2 px-3">{collapsed ? '' : 'Platform'}</p>
          <div className="space-y-0.5">
            <AdminNavItem to="/settings" icon={Settings} name="Settings" collapsed={collapsed} />
          </div>
        </div>
      </nav>

      <div className="border-t border-hairline p-3">
        <div className={`flex items-center rounded-md border border-hairline bg-sunken/60 p-2.5 ${collapsed ? 'justify-center' : 'justify-between'}`}>
          {!collapsed && (
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-critical/30 bg-critical/10 font-mono text-xs font-semibold text-critical">
                {user?.name?.charAt(0) || '?'}
              </div>
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-ink">{user?.name || 'Administrator'}</p>
                <p className="mt-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-critical">Administrator</p>
              </div>
            </div>
          )}
          <button
            aria-label="Sign out"
            onClick={handleLogout}
            className="rounded p-1.5 text-ink-mute transition-colors hover:bg-critical/10 hover:text-critical"
          >
            <LogOut size={collapsed ? 16 : 15} />
          </button>
        </div>
      </div>
    </aside>
  );
}

function AdminNavItem({ to, icon: Icon, name, collapsed, end }: { to: string; icon: typeof Activity; name: string; collapsed: boolean; end?: boolean }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `group relative flex items-center gap-3 rounded-md px-3 py-2 text-xs font-medium transition-colors ${
          isActive
            ? 'bg-critical/10 text-critical'
            : 'text-ink-mute hover:bg-raised hover:text-ink'
        } ${collapsed ? 'justify-center' : ''}`
      }
      title={collapsed ? name : undefined}
    >
      {({ isActive }) => (
        <>
          {/* Active rail — restricted-area red */}
          <span
            className={`absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-full bg-critical transition-opacity ${isActive ? 'opacity-100' : 'opacity-0'}`}
          />
          <Icon size={collapsed ? 18 : 15} className={isActive ? 'text-critical' : 'text-ink-faint transition-colors group-hover:text-ink-dim'} />
          {!collapsed && name}
        </>
      )}
    </NavLink>
  );
}
