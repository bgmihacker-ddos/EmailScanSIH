import { ReactNode, useState, useEffect } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, MailSearch, ShieldAlert, History, Settings, FolderKanban,
  Globe2, BarChart3, LogOut, Activity, Radar
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { SecurityEnvironmentBackground, SecurityProfile } from '../common/SecurityEnvironmentBackground';
import { TopBar } from './TopBar';

export function UserLayout({ children }: { children: ReactNode }) {
  const location = useLocation();
  const segment = location.pathname.split('/')[1] || 'dashboard';
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [profile, setProfile] = useState<SecurityProfile>('dashboard');

  useEffect(() => {
    if (segment === 'analyze' || segment === 'analysis') setProfile('analyze');
    else if (segment === 'live-threat') setProfile('live_threat');
    else if (segment === 'dashboard') setProfile('dashboard');
    else if (segment === 'indicators') setProfile('indicators');
    else setProfile('investigation');
  }, [segment]);

  return (
    <div className="flex h-screen overflow-hidden bg-deck font-sans text-ink antialiased">
      <SecurityEnvironmentBackground profile={profile} intensity="subtle" />

      <UserSidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />

      <div className="relative z-10 flex min-w-0 flex-1 flex-col overflow-hidden">
        <TopBar />

        <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}

function UserSidebar({ collapsed, onToggle }: { collapsed: boolean, onToggle: () => void }) {
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
          <div className="cursor-pointer rounded-md border border-hairline-strong bg-raised p-2 text-accent transition-colors hover:border-accent" onClick={onToggle}>
            <Radar size={collapsed ? 18 : 19} />
          </div>
          {!collapsed && (
            <div className="cursor-pointer" onClick={onToggle}>
              <h1 className="text-[13px] font-bold tracking-wide text-ink">EMAIL THREAT</h1>
              <p className="font-mono text-[9px] font-semibold tracking-[0.2em] text-accent">FORENSIC INTELLIGENCE</p>
            </div>
          )}
        </div>
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto p-3">
        <NavGroup label="Operations" collapsed={collapsed}>
          <NavItem to="/dashboard" icon={LayoutDashboard} name="Security overview" collapsed={collapsed} />
          <NavItem to="/analyze" icon={MailSearch} name="Analyze email" collapsed={collapsed} />
        </NavGroup>

        <NavGroup label="Threat intelligence" collapsed={collapsed}>
          <NavItem to="/live-threat" icon={Globe2} name="Live threat" collapsed={collapsed} />
          <NavItem to="/threats" icon={ShieldAlert} name="Threats" collapsed={collapsed} />
          <NavItem to="/indicators" icon={Activity} name="Indicators" collapsed={collapsed} />
        </NavGroup>

        <NavGroup label="Investigations" collapsed={collapsed}>
          <NavItem to="/history" icon={History} name="History" collapsed={collapsed} />
          <NavItem to="/reports" icon={BarChart3} name="Reports" collapsed={collapsed} />
          <NavItem to="/cases" icon={FolderKanban} name="Cases" collapsed={collapsed} />
        </NavGroup>

        <NavGroup label="Platform" collapsed={collapsed}>
          <NavItem to="/settings" icon={Settings} name="Settings" collapsed={collapsed} />
        </NavGroup>
      </nav>

      <div className="border-t border-hairline p-3">
        <div className={`flex items-center rounded-md border border-hairline bg-sunken/60 p-2.5 ${collapsed ? 'justify-center' : 'justify-between'}`}>
          {!collapsed && (
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-hairline-strong bg-raised font-mono text-xs font-semibold text-accent">
                {user?.name?.charAt(0) || '?'}
              </div>
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-ink">{user?.name || 'Analyst'}</p>
                <p className="mt-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-ink-mute">{user?.role || 'user'}</p>
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

function NavGroup({ label, children, collapsed }: { label: string; children: ReactNode; collapsed: boolean }) {
  if (collapsed) {
    return <div className="space-y-1">{children}</div>;
  }
  return (
    <div>
      <p className="soc-label mb-2 px-3">{label}</p>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function NavItem({ to, icon: Icon, name, collapsed }: { to: string; icon: typeof Activity; name: string; collapsed: boolean }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `group relative flex items-center gap-3 rounded-md px-3 py-2 text-xs font-medium transition-colors ${
          isActive
            ? 'bg-accent-soft text-accent'
            : 'text-ink-mute hover:bg-raised hover:text-ink'
        } ${collapsed ? 'justify-center' : ''}`
      }
      title={collapsed ? name : undefined}
    >
      {({ isActive }) => (
        <>
          {/* Active rail — accent bar on the leading edge */}
          <span
            className={`absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-full bg-accent transition-opacity ${isActive ? 'opacity-100' : 'opacity-0'}`}
          />
          <Icon size={collapsed ? 18 : 15} className={isActive ? 'text-accent' : 'text-ink-faint transition-colors group-hover:text-ink-dim'} />
          {!collapsed && name}
        </>
      )}
    </NavLink>
  );
}
