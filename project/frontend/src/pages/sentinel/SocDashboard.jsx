import React, { useEffect, useState } from 'react';
import { Icon, NoRunPanel, formatCount } from '../../sentinel/common';
import { getLogs } from '../../services/api';

/** Derives the SOC threat level from the last run's severity mix. */
function threatLevel(report) {
  if (!report || !report.anomalies_count) {
    return { label: 'NOMINAL', sub: 'NO ACTIVE THREATS', color: 'text-primary-container', dot: 'bg-primary-container', pulse: false };
  }
  const sev = Object.fromEntries((report.severities || []).map((s) => [s.name, s.value]));
  if (sev.Critical) return { label: 'CRITICAL', sub: `${sev.Critical} CRITICAL FLOWS`, color: 'text-error', dot: 'bg-error', pulse: true };
  if (sev.High) return { label: 'ELEVATED', sub: `${sev.High} HIGH-SEVERITY FLOWS`, color: 'text-orange-300', dot: 'bg-orange-300', pulse: true };
  return { label: 'GUARDED', sub: `${report.anomalies_count} ANOMALIES`, color: 'text-primary-container', dot: 'bg-primary-container', pulse: false };
}

function RingCard({ pct, stroke, title, subtitle, footnote }) {
  const dash = 175;
  const offset = pct == null ? dash : dash - (dash * Math.min(pct, 100)) / 100;
  return (
    <div className="glass-panel p-6 flex items-center gap-6">
      <div className="w-16 h-16 rounded-full border-4 border-white/5 flex items-center justify-center relative shrink-0">
        <svg className="absolute inset-0 w-full h-full -rotate-90">
          <circle cx="32" cy="32" fill="none" r="28" stroke={stroke} strokeDasharray={dash} strokeDashoffset={offset} strokeWidth="4" strokeLinecap="round" />
        </svg>
        <span className="font-bold text-sm" style={{ color: stroke }}>{pct == null ? '—' : `${pct.toFixed(1)}%`}</span>
      </div>
      <div>
        <h3 className="text-label-caps text-on-surface-variant mb-1 uppercase tracking-widest">{title}</h3>
        <p className="font-geist text-headline-md text-white">{subtitle}</p>
        <p className="text-[10px] text-on-surface-variant mt-1">{footnote}</p>
      </div>
    </div>
  );
}

/** Animated source→target campaign visual (replaces the mock world map). */
function CampaignVector({ report }) {
  const campaign = (report?.campaigns || [])[0];
  if (!campaign) {
    return (
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-label-caps tracking-widest text-on-surface-variant/40 uppercase">No active campaigns detected</span>
      </div>
    );
  }
  const detail = (report.attack_details || []).find((d) => campaign.label.includes(d.name) || d.name === campaign.attack_type);
  const sources = (detail?.top_sources || []).slice(0, 6);
  const H = 360;
  const targetX = 640;
  const targetY = H / 2;
  return (
    <svg className="absolute inset-0 w-full h-full" viewBox={`0 0 800 ${H}`} preserveAspectRatio="xMidYMid meet">
      {sources.map((s, i) => {
        const y = 50 + (i * (H - 100)) / Math.max(sources.length - 1, 1);
        return (
          <g key={s.ip}>
            <circle cx="120" cy={y} r="4" fill="#ffb4ab" opacity="0.9" />
            <text x="112" y={y + 4} textAnchor="end" fill="#b9cacb" fontSize="10" fontFamily="Space Mono, monospace">{s.ip}</text>
            <path
              className="map-line"
              d={`M 120,${y} Q ${(120 + targetX) / 2},${(y + targetY) / 2 - 60} ${targetX},${targetY}`}
              fill="none"
              stroke="#ffb4ab"
              strokeWidth="1.5"
              opacity="0.4"
              style={{ animationDelay: `${i * 0.6}s` }}
            />
          </g>
        );
      })}
      <circle cx={targetX} cy={targetY} r="40" fill="url(#target-gradient)" className="animate-pulse" />
      <circle cx={targetX} cy={targetY} r="6" fill="#00f0ff" />
      <text x={targetX} y={targetY + 28} textAnchor="middle" fill="#dbfcff" fontSize="12" fontFamily="Space Mono, monospace" fontWeight="bold">
        {campaign.target}
      </text>
      <defs>
        <radialGradient id="target-gradient">
          <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#00f0ff" stopOpacity="0" />
        </radialGradient>
      </defs>
    </svg>
  );
}

const LOG_COLOR = { ERROR: 'text-error font-bold', WARNING: 'text-yellow-300', INFO: 'text-on-surface' };

export default function SocDashboard({ lastRun, lastRunTime, modelHealth, onNavigate }) {
  const [logs, setLogs] = useState([]);
  const report = lastRun;
  const level = threatLevel(report);

  useEffect(() => {
    let mounted = true;
    async function poll() {
      try {
        const data = await getLogs(10);
        if (mounted) setLogs([...data].reverse());
      } catch { /* backend offline — keep last logs */ }
    }
    poll();
    const id = setInterval(poll, 4000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  const healthAssets = Object.entries(modelHealth?.health_monitor || {});
  const healthyCount = healthAssets.filter(([, v]) => v === 'Healthy').length;
  const healthPct = healthAssets.length ? (healthyCount / healthAssets.length) * 100 : 0;

  const avgConfidence = report?.anomalies?.length
    ? report.anomalies.reduce((a, f) => a + (f.confidence || 0), 0) / report.anomalies.length
    : null;
  const accuracy = report?.classification_report?.accuracy ?? null;
  const benignPct = report?.total_flows ? (report.normal_count / report.total_flows) * 100 : null;
  const topCampaign = (report?.campaigns || [])[0];

  return (
    <div className="space-y-panel-gap">
      {/* Hero metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-panel-gap">
        <div className="glass-panel p-6 relative overflow-hidden group hover:border-primary/40 transition-all duration-300">
          <div className="scan-line" />
          <div className="flex justify-between items-start mb-4">
            <span className="text-label-caps text-on-surface-variant tracking-widest uppercase">Model Health</span>
            <Icon name="lan" className="text-primary-container opacity-50" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-geist text-display-lg text-primary neon-glow-cyan">{healthPct.toFixed(0)}%</span>
            <span className="text-xs text-on-surface-variant">{healthyCount}/{healthAssets.length || 4} assets</span>
          </div>
          <p className="mt-4 text-[10px] font-label-mono text-on-surface-variant truncate">
            {modelHealth?.pipeline_type || 'Unsupervised Ensemble + DDoS Rule Engine'}
          </p>
        </div>

        <div className="glass-panel p-6 group hover:border-primary/40 transition-all duration-300">
          <div className="flex justify-between items-start mb-4">
            <span className="text-label-caps text-on-surface-variant tracking-widest uppercase">Analyzed Flows</span>
            <Icon name="leak_add" className="text-secondary opacity-50" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-geist text-display-lg text-on-surface font-bold">{formatCount(report?.total_flows || 0)}</span>
            <span className="text-xs text-secondary-fixed-dim">LAST RUN</span>
          </div>
          <div className="mt-4 flex gap-1 items-end h-8">
            <div className="flex-1 bg-secondary/10 h-2 rounded-full overflow-hidden">
              <div className="bg-secondary h-full" style={{ width: `${benignPct ?? 0}%` }} />
            </div>
          </div>
        </div>

        <div className="glass-panel p-6 group hover:border-primary/40 transition-all duration-300">
          <div className="flex justify-between items-start mb-4">
            <span className="text-label-caps text-on-surface-variant tracking-widest uppercase">Anomalies</span>
            <Icon name="data_thresholding" className="text-primary-fixed opacity-50" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-geist text-display-lg text-on-surface font-bold">{formatCount(report?.anomalies_count || 0)}</span>
            <span className="text-xs text-on-surface-variant">{report ? `${report.threat_ratio}% OF TRAFFIC` : 'NO DATA'}</span>
          </div>
          <div className="mt-4 flex items-end gap-0.5 h-8">
            {(report?.timeline || []).map((t, i) => {
              const max = Math.max(...report.timeline.map((x) => x.attacks), 1);
              return <div key={i} className="flex-1 bg-error/60 rounded-t-sm" style={{ height: `${Math.max((t.attacks / max) * 100, 4)}%` }} />;
            })}
          </div>
        </div>

        <div className="glass-panel p-6 relative group hover:border-error/40 transition-all duration-300">
          <div className="flex justify-between items-start mb-4">
            <span className="text-label-caps text-on-surface-variant tracking-widest uppercase">Threat Level</span>
            <div className={`w-3 h-3 rounded-full ${level.dot} ${level.pulse ? 'pulse-critical' : ''}`} />
          </div>
          <div className="flex flex-col">
            <span className={`font-geist text-display-lg uppercase tracking-tight ${level.color}`}>{level.label}</span>
            <span className={`font-label-mono text-label-mono ${level.color} opacity-80`}>{level.sub}</span>
          </div>
          <div className="mt-4 flex items-center justify-between">
            <span className="text-[10px] text-on-surface-variant uppercase">Last analysis</span>
            <span className="text-[10px] font-bold text-on-surface">{lastRunTime || 'never'}</span>
          </div>
        </div>
      </div>

      {/* Campaign vector visual */}
      <div className="glass-panel p-8 relative min-h-[420px] overflow-hidden">
        <div className="absolute top-8 left-8 z-10">
          <h2 className="font-geist text-headline-md text-white mb-1">Live Threat Vector</h2>
          <p className="text-body-md text-on-surface-variant">Distributed sources converging on the primary campaign target</p>
        </div>
        {report ? (
          <>
            <div className="absolute top-8 right-8 z-10 flex flex-col gap-2">
              <div className="bg-background/80 backdrop-blur p-3 rounded-lg border border-white/5 flex items-center gap-4">
                <div className="flex flex-col">
                  <span className="text-[10px] text-on-surface-variant uppercase">Vector</span>
                  <span className="text-xs font-label-mono font-bold text-error">{topCampaign?.label || 'None'}</span>
                </div>
                <div className="w-px h-8 bg-white/10" />
                <div className="flex flex-col">
                  <span className="text-[10px] text-on-surface-variant uppercase">Sources</span>
                  <span className="text-xs font-label-mono font-bold text-primary">{topCampaign?.num_sources ?? 0}</span>
                </div>
              </div>
              <div className="bg-background/80 backdrop-blur p-3 rounded-lg border border-white/5 flex items-center justify-between gap-6">
                <span className="text-[10px] text-on-surface-variant uppercase">Campaigns</span>
                <span className="text-sm font-bold text-error">{report.campaigns?.length || 0}</span>
              </div>
            </div>
            <div className="absolute inset-0 top-16">
              <CampaignVector report={report} />
            </div>
          </>
        ) : (
          <div className="absolute inset-0 flex items-center justify-center">
            <NoRunPanel onNavigate={onNavigate} />
          </div>
        )}
      </div>

      {/* Ring metric cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-panel-gap">
        <RingCard
          pct={avgConfidence}
          stroke="#00f0ff"
          title="Ensemble Confidence"
          subtitle={avgConfidence == null ? 'Awaiting Data' : avgConfidence >= 80 ? 'High Fidelity' : 'Moderate'}
          footnote="Mean anomaly confidence — Isolation Forest ∪ Autoencoder"
        />
        <RingCard
          pct={accuracy}
          stroke="#d1bcff"
          title="Detection Accuracy"
          subtitle={accuracy == null ? 'Unlabeled Data' : accuracy >= 90 ? 'Superior Precision' : 'Validated'}
          footnote={accuracy == null ? 'Available when the dataset carries ground-truth labels' : 'Validated against dataset labels'}
        />
        <RingCard
          pct={benignPct}
          stroke="#e5e2e1"
          title="Benign Traffic"
          subtitle={benignPct == null ? 'Awaiting Data' : 'Baseline Match'}
          footnote={report ? `${report.normal_count} of ${report.total_flows} flows matched the benign baseline` : '—'}
        />
      </div>

      {/* Live system log terminal */}
      <div className="glass-panel overflow-hidden">
        <div className="bg-surface-container-highest/50 px-4 py-2 border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-error/40" />
              <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/40" />
              <div className="w-2.5 h-2.5 rounded-full bg-green-500/40" />
            </div>
            <span className="font-label-mono text-[10px] text-on-surface-variant ml-4 tracking-wider">LIVE_SYSTEM_LOGS: AEGIS-IDS-BACKEND</span>
          </div>
          <span className="font-label-mono text-[10px] text-primary-container animate-pulse">POLLING…</span>
        </div>
        <div className="p-4 font-label-mono text-[11px] leading-relaxed text-on-surface-variant h-44 overflow-y-auto bg-black/40">
          {logs.length === 0 && <div className="italic opacity-50">Waiting for backend log stream…</div>}
          {logs.map((l) => (
            <div key={l.id} className="flex gap-4">
              <span className="text-primary-container/40 shrink-0">{(l.timestamp || '').split(' ')[1] || l.timestamp}</span>
              <span className={LOG_COLOR[l.level] || 'text-on-surface'}>{l.message}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
