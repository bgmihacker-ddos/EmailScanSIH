import { useState } from 'react';
import { useToast } from '../../context/ToastContext';
import { Shield, Settings as SettingsIcon, Lock, Search, Bell, Database } from 'lucide-react';

export default function AdminSettings() {
  const { addToast } = useToast();
  const [activeTab, setActiveTab] = useState<'platform' | 'security' | 'detection' | 'intelligence' | 'notifications' | 'system'>('platform');

  const [settings, setSettings] = useState(() => {
    try {
      const saved = localStorage.getItem('adminSettings');
      if (saved) return JSON.parse(saved);
    } catch {
      // Ignore malformed local preferences and use defaults below.
    }
    return {
      // Platform
      platformName: 'Email Threat Intelligence',
      environment: 'production',
      maintenanceMode: false,
      sessionTimeout: '30',
      // Security
      requireMFA: true,
      loginProtection: true,
      sessionSecurity: 'strict',
      ipRestrictions: '',
      // Detection
      detectionThreshold: 'high',
      autoClassification: true,
      threatScoring: 'dynamic',
      urlAnalysis: true,
      headerAnalysis: true,
      // Intelligence
      autoSync: true,
      syncInterval: '15',
      enrichment: true,
      // Notifications
      criticalAlerts: true,
      adminAlerts: true,
      healthAlerts: false,
      // System
      logRetention: '90',
      auditLogging: true,
      debugMode: false,
    };
  });

  const handleSave = () => {
    // Persistent save to localStorage
    localStorage.setItem('adminSettings', JSON.stringify(settings));
    addToast('Administrative settings saved successfully', 'success');
  };

  const tabs = [
    { id: 'platform', label: 'Platform', icon: <SettingsIcon size={14} /> },
    { id: 'security', label: 'Security', icon: <Lock size={14} /> },
    { id: 'detection', label: 'Threat Detection', icon: <Search size={14} /> },
    { id: 'intelligence', label: 'Threat Intelligence', icon: <Shield size={14} /> },
    { id: 'notifications', label: 'Notifications', icon: <Bell size={14} /> },
    { id: 'system', label: 'System', icon: <Database size={14} /> },
  ] as const;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-ink uppercase tracking-wider flex items-center gap-2">
            <Lock className="text-accent" />
            Administrative Settings
          </h1>
          <p className="text-xs text-ink-mute">Configure global platform behavior, security protocols, and engine tuning</p>
        </div>
        <button
          onClick={handleSave}
          className="px-4 py-2 bg-accent/10 hover:bg-accent-soft border border-hairline-strong text-ink-dim text-xs font-bold rounded"
        >
          Save Changes
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-hairline flex gap-1 overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-3 text-xs font-bold transition-colors whitespace-nowrap ${
              activeTab === tab.id
                ? 'border-b-2 border-accent/60 text-accent'
                : 'text-ink-mute hover:text-ink-dim hover:bg-raised'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      <div className="bg-raised p-5 rounded border border-hairline">
        {activeTab === 'platform' && (
          <div className="space-y-4">
            <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-4">Platform Configuration</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Platform Name</label>
                <input
                  type="text"
                  value={settings.platformName}
                  onChange={(e) => setSettings({ ...settings, platformName: e.target.value })}
                  className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink rounded focus:outline-none focus:border-accent/60"
                />
              </div>
              <div>
                <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Environment</label>
                <select
                  value={settings.environment}
                  onChange={(e) => setSettings({ ...settings, environment: e.target.value })}
                  className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink-dim rounded focus:outline-none focus:border-accent/60"
                >
                  <option value="development">Development</option>
                  <option value="staging">Staging</option>
                  <option value="production">Production</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Session Timeout (min)</label>
                <input
                  type="number"
                  value={settings.sessionTimeout}
                  onChange={(e) => setSettings({ ...settings, sessionTimeout: e.target.value })}
                  className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink rounded focus:outline-none focus:border-accent/60"
                />
              </div>
              <div className="flex items-center justify-between p-3 bg-raised border border-hairline rounded">
                <div>
                  <p className="text-sm text-ink font-bold">Maintenance Mode</p>
                  <p className="text-xs text-ink-mute">Lock out all non-admin users</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.maintenanceMode}
                    onChange={(e) => setSettings({ ...settings, maintenanceMode: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-raised peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-hairline-strong after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-accent"></div>
                </label>
              </div>
            </div>
          </div>
        )}

        {/* Similar patterns for the other 5 tabs following strict requirements */}
        {activeTab === 'security' && (
          <div className="space-y-4">
             <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-4">Security Settings</h2>
             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
               {[
                 { key: 'requireMFA', label: 'Require MFA for all users', desc: 'Enforce multi-factor auth across platform' },
                 { key: 'loginProtection', label: 'Brute Force Protection', desc: 'Auto-lock accounts after 5 failed attempts' },
               ].map((item) => (
                 <div key={item.key} className="flex items-center justify-between p-3 bg-raised border border-hairline rounded">
                    <div>
                      <p className="text-sm text-ink font-bold">{item.label}</p>
                      <p className="text-xs text-ink-mute">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings[item.key as keyof typeof settings] as boolean}
                        onChange={(e) => setSettings({ ...settings, [item.key]: e.target.checked })}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-raised peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-hairline-strong after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-accent"></div>
                    </label>
                  </div>
               ))}
               <div>
                  <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Session Security</label>
                  <select
                    value={settings.sessionSecurity}
                    onChange={(e) => setSettings({ ...settings, sessionSecurity: e.target.value })}
                    className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink-dim rounded focus:outline-none focus:border-accent/60"
                  >
                    <option value="strict">Strict (Bind to IP)</option>
                    <option value="standard">Standard</option>
                  </select>
               </div>
               <div>
                  <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">IP Restrictions (CIDR)</label>
                  <input
                    type="text"
                    placeholder="e.g. 192.168.1.0/24"
                    value={settings.ipRestrictions}
                    onChange={(e) => setSettings({ ...settings, ipRestrictions: e.target.value })}
                    className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink rounded focus:outline-none focus:border-accent/60"
                  />
               </div>
             </div>
          </div>
        )}

        {activeTab === 'detection' && (
          <div className="space-y-4">
             <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-4">Threat Detection Engine</h2>
             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
               {[
                 { key: 'autoClassification', label: 'Automatic Classification', desc: 'Engine automatically categorizes threats' },
                 { key: 'urlAnalysis', label: 'Deep URL Analysis', desc: 'Explode and sandbox suspicious URLs' },
                 { key: 'headerAnalysis', label: 'Heuristic Header Analysis', desc: 'Advanced spoofing and SPF/DKIM validation' },
               ].map((item) => (
                 <div key={item.key} className="flex items-center justify-between p-3 bg-raised border border-hairline rounded">
                    <div>
                      <p className="text-sm text-ink font-bold">{item.label}</p>
                      <p className="text-xs text-ink-mute">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings[item.key as keyof typeof settings] as boolean}
                        onChange={(e) => setSettings({ ...settings, [item.key]: e.target.checked })}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-raised peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-hairline-strong after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-accent"></div>
                    </label>
                  </div>
               ))}
               <div>
                  <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Detection Threshold</label>
                  <select
                    value={settings.detectionThreshold}
                    onChange={(e) => setSettings({ ...settings, detectionThreshold: e.target.value })}
                    className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink-dim rounded focus:outline-none focus:border-accent/60"
                  >
                    <option value="aggressive">Aggressive</option>
                    <option value="high">High Sensitivity</option>
                    <option value="balanced">Balanced</option>
                    <option value="relaxed">Relaxed</option>
                  </select>
               </div>
               <div>
                  <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Threat Scoring Model</label>
                  <select
                    value={settings.threatScoring}
                    onChange={(e) => setSettings({ ...settings, threatScoring: e.target.value })}
                    className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink-dim rounded focus:outline-none focus:border-accent/60"
                  >
                    <option value="dynamic">Dynamic AI Scoring</option>
                    <option value="static">Static Ruleset</option>
                    <option value="hybrid">Hybrid Engine</option>
                  </select>
               </div>
             </div>
          </div>
        )}

        {activeTab === 'intelligence' && (
          <div className="space-y-4">
             <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-4">Threat Intelligence Operations</h2>
             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
               {[
                 { key: 'autoSync', label: 'Automatic Sync', desc: 'Pull indicators from configured providers' },
                 { key: 'enrichment', label: 'Intelligence Enrichment', desc: 'Automatically enrich domains and IPs' },
               ].map((item) => (
                 <div key={item.key} className="flex items-center justify-between p-3 bg-raised border border-hairline rounded">
                    <div>
                      <p className="text-sm text-ink font-bold">{item.label}</p>
                      <p className="text-xs text-ink-mute">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings[item.key as keyof typeof settings] as boolean}
                        onChange={(e) => setSettings({ ...settings, [item.key]: e.target.checked })}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-raised peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-hairline-strong after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-accent"></div>
                    </label>
                  </div>
               ))}
               <div>
                  <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Sync Interval (Minutes)</label>
                  <input
                    type="number"
                    value={settings.syncInterval}
                    onChange={(e) => setSettings({ ...settings, syncInterval: e.target.value })}
                    className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink rounded focus:outline-none focus:border-accent/60"
                  />
               </div>
             </div>
          </div>
        )}

        {activeTab === 'notifications' && (
          <div className="space-y-4">
             <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-4">System Notifications</h2>
             <div className="grid grid-cols-1 gap-4 max-w-2xl">
               {[
                 { key: 'criticalAlerts', label: 'Critical Threat Alerts', desc: 'Push notification on new critical threats' },
                 { key: 'adminAlerts', label: 'Administrative Alerts', desc: 'Notify on configuration changes' },
                 { key: 'healthAlerts', label: 'System Health Alerts', desc: 'Notify when services are degraded' },
               ].map((item) => (
                 <div key={item.key} className="flex items-center justify-between p-3 bg-raised border border-hairline rounded">
                    <div>
                      <p className="text-sm text-ink font-bold">{item.label}</p>
                      <p className="text-xs text-ink-mute">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings[item.key as keyof typeof settings] as boolean}
                        onChange={(e) => setSettings({ ...settings, [item.key]: e.target.checked })}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-raised peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-hairline-strong after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-accent"></div>
                    </label>
                  </div>
               ))}
             </div>
          </div>
        )}

        {activeTab === 'system' && (
          <div className="space-y-4">
             <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-4">System Settings</h2>
             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
               {[
                 { key: 'auditLogging', label: 'Audit Logging', desc: 'Record all user and system events' },
                 { key: 'debugMode', label: 'Debug Mode', desc: 'Enable verbose engine logging' },
               ].map((item) => (
                 <div key={item.key} className="flex items-center justify-between p-3 bg-raised border border-hairline rounded">
                    <div>
                      <p className="text-sm text-ink font-bold">{item.label}</p>
                      <p className="text-xs text-ink-mute">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings[item.key as keyof typeof settings] as boolean}
                        onChange={(e) => setSettings({ ...settings, [item.key]: e.target.checked })}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-raised peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-hairline-strong after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-critical"></div>
                    </label>
                  </div>
               ))}
               <div>
                  <label className="block text-xs text-ink-mute uppercase tracking-wider mb-1">Log Retention (Days)</label>
                  <select
                    value={settings.logRetention}
                    onChange={(e) => setSettings({ ...settings, logRetention: e.target.value })}
                    className="w-full bg-sunken border border-hairline px-3 py-2 text-sm text-ink-dim rounded focus:outline-none focus:border-accent/60"
                  >
                    <option value="30">30 Days</option>
                    <option value="90">90 Days</option>
                    <option value="180">180 Days</option>
                    <option value="365">1 Year</option>
                  </select>
               </div>
             </div>
          </div>
        )}
      </div>
    </div>
  );
}
