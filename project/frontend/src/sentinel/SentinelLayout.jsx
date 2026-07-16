import React, { useEffect, useState } from 'react';
import { Icon } from './common';
import ShaderBackground from './ShaderBackground';

const NAV_MAIN = [
  { id: 'soc', icon: 'dashboard', label: 'SOC Dashboard' },
  { id: 'pipeline', icon: 'security', label: 'Detection Pipeline' },
  { id: 'explorer', icon: 'hub', label: 'Flow Explorer' },
  { id: 'classifier', icon: 'shield_locked', label: 'DDoS Classifier' },
];

const NAV_LEGACY = [
  { id: 'dashboard', icon: 'analytics', label: 'Analytics (Live)' },
  { id: 'online', icon: 'sensors', label: 'Live Capture' },
  { id: 'history', icon: 'description', label: 'Intelligence Reports' },
];

export default function SentinelLayout({ active, onNavigate, modelHealth, onSearch, children }) {
  const [clock, setClock] = useState('');
  const [search, setSearch] = useState('');

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString('en-GB'));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const healthOk = modelHealth?.status === 'Green';

  function NavItem({ item }) {
    const isActive = active === item.id;
    return (
      <button
        onClick={() => onNavigate(item.id)}
        className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg font-medium transition-all duration-200 cursor-pointer text-left ${
          isActive
            ? 'text-primary font-bold border-r-2 border-primary-container bg-primary/5'
            : 'text-on-surface-variant hover:bg-white/5 hover:text-primary'
        }`}
      >
        <Icon name={item.icon} fill={isActive} className="text-[20px]" />
        <span className="text-body-md">{item.label}</span>
      </button>
    );
  }

  return (
    <div className="sentinel-root min-h-screen">
      <ShaderBackground opacity={0.25} />

      {/* SideNavBar */}
      <aside className="fixed left-0 top-0 h-full w-64 border-r border-white/10 bg-surface/70 backdrop-blur-xl flex flex-col py-6 z-[60]">
        <div className="px-6 mb-6">
          <h1 className="font-geist text-[28px] leading-8 font-bold text-primary-container tracking-tighter">Sentinel AI</h1>
          <p className="text-label-caps text-on-surface-variant uppercase mt-1 tracking-widest">Vigilance System</p>
        </div>
        <nav className="flex-1 flex flex-col gap-1 px-3 overflow-y-auto">
          {NAV_MAIN.map((item) => <NavItem key={item.id} item={item} />)}
          <div className="my-3 mx-4 h-px bg-white/5" />
          {NAV_LEGACY.map((item) => <NavItem key={item.id} item={item} />)}
        </nav>
        <div className="mt-auto px-4 pt-4 border-t border-white/5 flex flex-col gap-1">
          <div className="flex items-center gap-2 mb-3 px-2">
            <div
              className={`w-2 h-2 rounded-full ${healthOk ? 'bg-primary-container shadow-[0_0_8px_rgba(0,240,255,0.8)]' : 'bg-error pulse-critical'}`}
            />
            <span className={`text-[10px] uppercase tracking-widest font-bold ${healthOk ? 'text-primary-container' : 'text-error'}`}>
              Models: {healthOk ? 'Optimal' : 'Degraded'}
            </span>
          </div>
          <button
            onClick={() => onNavigate('settings')}
            className={`flex items-center gap-3 px-2 py-2 font-medium transition-all duration-200 cursor-pointer ${
              active === 'settings' ? 'text-primary' : 'text-on-surface-variant hover:text-primary'
            }`}
          >
            <Icon name="settings" className="text-[18px]" />
            <span className="text-label-caps uppercase tracking-widest">Settings</span>
          </button>
          <div className="mt-3 flex items-center gap-3 px-2">
            <div className="w-8 h-8 rounded-full bg-primary-container/90 border border-primary/20 flex items-center justify-center text-black font-bold text-xs">
              SA
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-bold text-white">SOC Analyst</span>
              <span className="text-[10px] text-on-surface-variant">Active Session</span>
            </div>
          </div>
        </div>
      </aside>

      {/* TopAppBar */}
      <header className="fixed top-0 right-0 w-[calc(100%-16rem)] h-16 flex justify-between items-center px-gutter bg-surface/50 backdrop-blur-lg border-b border-white/10 z-50">
        <div className="flex items-center gap-4 flex-1">
          <form
            className="relative w-full max-w-md"
            onSubmit={(e) => {
              e.preventDefault();
              if (search.trim() && onSearch) onSearch(search.trim());
            }}
          >
            <Icon name="search" className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-[18px]" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-surface-container-lowest/50 border border-outline-variant/30 rounded-lg py-1.5 pl-10 pr-4 text-xs text-on-surface focus:ring-1 focus:ring-primary-container focus:border-primary-container outline-none transition-all placeholder:text-on-surface-variant/40"
              placeholder="Search flows by IP, attack type, or protocol…"
              type="text"
            />
          </form>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 px-3 py-1 bg-primary-container/10 border border-primary-container/20 rounded-full">
            <span className="w-2 h-2 rounded-full bg-primary-container shadow-[0_0_8px_rgba(0,240,255,0.8)]" />
            <span className="font-label-mono text-label-mono text-primary-container">SOC TIER 3</span>
          </div>
          <div className="h-6 w-px bg-white/10" />
          <div className="flex items-center gap-2">
            <span className="font-label-mono text-label-mono text-primary-container">AEGIS-IDS</span>
            <span className="font-label-mono text-label-mono text-on-surface-variant">{clock}</span>
          </div>
        </div>
      </header>

      {/* Main content canvas */}
      <main className="ml-64 pt-24 px-gutter pb-12 min-h-screen relative z-10">
        {children}
      </main>
    </div>
  );
}
