import React from 'react';
import { Icon, NoRunPanel, attackIcon, formatBytes, formatCount, severityStyle } from '../../sentinel/common';

/** Dominant severity of an attack_details entry. */
function dominantSeverity(severities) {
  for (const s of ['Critical', 'High', 'Medium', 'Low']) {
    if (severities?.[s]) return s;
  }
  return 'Low';
}

function AttackCard({ detail, onInspect }) {
  const sev = dominantSeverity(detail.severities);
  const s = severityStyle(sev);
  const conf = Math.round((detail.avg_rule_confidence || 0) * 100);
  const glow = sev === 'Critical' ? 'neon-glow-critical' : sev === 'High' || sev === 'Medium' ? 'neon-glow-elevated' : '';
  const topSrc = detail.top_sources?.[0];
  const spark = (detail.top_targets || []).length ? detail.top_targets : detail.top_sources || [];
  const sparkMax = Math.max(...spark.map((x) => x.flows), 1);

  return (
    <div className={`glass-panel p-6 relative overflow-hidden group ${glow}`}>
      <div className="flex justify-between items-start mb-6">
        <div className="flex gap-3 items-center">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${s.bg} ${s.text}`}>
            <Icon name={attackIcon(detail.name)} />
          </div>
          <div>
            <h3 className="font-geist text-[20px] font-semibold text-on-surface">{detail.name}</h3>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${s.bg} ${s.text} border ${s.border} uppercase tracking-wider`}>{sev}</span>
          </div>
        </div>
        <div className="text-right">
          <p className={`font-label-mono text-xl ${s.text}`}>{conf}%</p>
          <p className="text-[9px] text-label-caps text-on-surface-variant/60 uppercase tracking-widest">Rule Confidence</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="bg-black/20 p-3 rounded-lg border border-white/5">
          <p className="text-[10px] text-label-caps text-on-surface-variant/60 mb-1 uppercase tracking-widest">Packets / Volume</p>
          <p className="font-geist text-primary text-[18px] font-semibold">
            {formatCount(detail.total_pkts)} <span className="text-xs text-on-surface-variant">pkts · {formatBytes(detail.total_bytes)}</span>
          </p>
        </div>
        <div className="bg-black/20 p-3 rounded-lg border border-white/5">
          <p className="text-[10px] text-label-caps text-on-surface-variant/60 mb-1 uppercase tracking-widest">Top Attacker</p>
          <p className="font-label-mono text-primary text-[13px]">{topSrc ? topSrc.ip : '—'}</p>
          <p className="text-[9px] text-on-surface-variant font-label-mono">{detail.unique_sources} UNIQUE SOURCES</p>
        </div>
        <div className="bg-black/20 p-3 rounded-lg border border-white/5">
          <p className="text-[10px] text-label-caps text-on-surface-variant/60 mb-1 uppercase tracking-widest">Rate</p>
          <p className="font-geist text-primary text-[16px] font-semibold">
            {detail.avg_pps} <span className="text-xs text-on-surface-variant">avg pkt/s · peak {detail.peak_pps}</span>
          </p>
        </div>
        <div className="bg-black/20 p-3 rounded-lg border border-white/5">
          <p className="text-[10px] text-label-caps text-on-surface-variant/60 mb-1 uppercase tracking-widest">Target Ports</p>
          <p className="font-label-mono text-primary text-[12px] truncate">{(detail.dst_ports || []).slice(0, 6).join(', ') || '—'}</p>
        </div>
      </div>

      {/* Flow distribution across top targets */}
      {spark.length > 0 && (
        <div className="h-12 w-full opacity-50 mb-4 flex items-end gap-1" title="Flow share across top targets">
          {spark.map((x, i) => (
            <div
              key={i}
              className={`flex-1 rounded-t-sm ${s.dot}`}
              style={{ height: `${Math.max((x.flows / sparkMax) * 100, 8)}%`, opacity: 0.3 + 0.7 * (x.flows / sparkMax) }}
            />
          ))}
        </div>
      )}

      {detail.example_evidence?.length > 0 && (
        <p className="text-[10px] text-on-surface-variant italic mb-4 leading-relaxed">“{detail.example_evidence[0]}”</p>
      )}

      <button
        onClick={() => onInspect(detail.name)}
        className="w-full py-2.5 bg-white/5 hover:bg-white/10 rounded-lg text-sm font-medium border border-white/10 transition-all flex items-center justify-center gap-2 cursor-pointer"
      >
        View {detail.flows} flows <Icon name="chevron_right" className="text-sm" />
      </button>
    </div>
  );
}

export default function DdosClassifier({ lastRun, onNavigate, onInspectType }) {
  const report = lastRun;

  if (!report) {
    return (
      <div className="space-y-6">
        <h2 className="font-geist text-headline-lg text-primary">Attack Classification</h2>
        <NoRunPanel onNavigate={onNavigate} />
      </div>
    );
  }

  const details = report.attack_details || [];
  const severities = report.severities || [];
  const sevTotal = severities.reduce((a, s) => a + s.value, 0) || 1;
  const mitigatedPct = report.total_flows ? Math.round((report.normal_count / report.total_flows) * 100) : 0;
  const gaugeDash = 502;
  const gaugeOffset = gaugeDash - (gaugeDash * Math.min(report.threat_ratio, 100)) / 100;
  const topCampaign = (report.campaigns || [])[0];

  return (
    <div className="flex gap-panel-gap flex-col 2xl:flex-row">
      {/* Classification cards */}
      <div className="flex-1">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="font-geist text-headline-lg text-primary">Attack Classification</h2>
            <p className="text-on-surface-variant text-body-md mt-1">
              Stage 2 rule-engine verdicts aggregated per DDoS subtype — packets, sources, and evidence per vector.
            </p>
          </div>
          <button
            onClick={() => onNavigate('pipeline')}
            className="px-4 py-2 bg-primary-container text-black font-bold rounded-lg text-sm flex items-center gap-2 hover:shadow-neon-cyan-strong transition-all cursor-pointer"
          >
            <Icon name="refresh" className="text-sm" /> New Analysis
          </button>
        </div>

        {details.length === 0 ? (
          <div className="glass-panel p-12 text-center">
            <Icon name="verified_user" className="text-primary-container/50" style={{ fontSize: '48px' }} />
            <p className="text-on-surface-variant mt-4">No attack subtypes detected in the last analysis — all traffic matched the benign baseline.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {details.map((d) => <AttackCard key={d.name} detail={d} onInspect={onInspectType} />)}
          </div>
        )}
      </div>

      {/* Summary sidebar */}
      <div className="w-full 2xl:w-80 flex flex-col gap-6 shrink-0">
        {/* Anomaly gauge */}
        <div className="glass-panel p-6 border-primary-container/20">
          <h4 className="text-label-caps text-on-surface-variant/80 mb-6 tracking-widest uppercase">Total Anomalies</h4>
          <div className="relative w-48 h-48 mx-auto flex items-center justify-center">
            <svg className="w-full h-full -rotate-90">
              <circle cx="96" cy="96" fill="none" r="80" stroke="rgba(255,255,255,0.05)" strokeWidth="12" />
              <circle cx="96" cy="96" fill="none" r="80" stroke="url(#cyan_grad)" strokeDasharray={gaugeDash} strokeDashoffset={gaugeOffset} strokeLinecap="round" strokeWidth="12" />
              <defs>
                <linearGradient id="cyan_grad" x1="0%" x2="100%" y1="0%" y2="0%">
                  <stop offset="0%" style={{ stopColor: '#00f0ff', stopOpacity: 1 }} />
                  <stop offset="100%" style={{ stopColor: '#d1bcff', stopOpacity: 1 }} />
                </linearGradient>
              </defs>
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-geist text-[42px] leading-none text-primary font-bold">{report.anomalies_count.toLocaleString()}</span>
              <span className="text-label-caps text-[10px] text-on-surface-variant/60 uppercase tracking-widest mt-1">of {report.total_flows.toLocaleString()} flows</span>
            </div>
          </div>
          <div className="flex justify-between mt-6 px-2">
            <div className="text-center">
              <p className="text-error font-label-mono text-lg">{report.threat_ratio}%</p>
              <p className="text-label-caps text-[8px] text-on-surface-variant/60 uppercase tracking-widest">Threat Ratio</p>
            </div>
            <div className="w-px bg-white/10 h-8 mt-1" />
            <div className="text-center">
              <p className="text-primary-container font-label-mono text-lg">{mitigatedPct}%</p>
              <p className="text-label-caps text-[8px] text-on-surface-variant/60 uppercase tracking-widest">Benign</p>
            </div>
          </div>
        </div>

        {/* Severity distribution */}
        <div className="glass-panel p-6">
          <h4 className="text-label-caps text-on-surface-variant/80 mb-6 tracking-widest uppercase">Severity Distribution</h4>
          <div className="space-y-4">
            {severities.length === 0 && <p className="text-xs text-on-surface-variant italic">No anomalies.</p>}
            {severities.map((s) => {
              const pct = Math.round((s.value / sevTotal) * 100);
              const style = severityStyle(s.name);
              return (
                <div key={s.name}>
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs text-on-surface">{s.name} <span className="text-on-surface-variant">({s.value})</span></span>
                    <span className={`font-label-mono text-xs ${style.text}`}>{pct}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <div className={`${style.dot} h-full rounded-full ${style.pulse ? 'pulse-critical' : ''}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          {topCampaign && (
            <div className="mt-8 pt-6 border-t border-white/5">
              <div className="flex items-center gap-3 mb-4">
                <div className={`w-2 h-2 rounded-full ${topCampaign.distributed ? 'bg-error pulse-critical' : 'bg-primary-container'}`} />
                <span className="text-xs font-medium text-on-surface">{topCampaign.distributed ? 'Distributed Campaign Active' : 'Primary Campaign'}</span>
              </div>
              <div className={`p-3 rounded-lg border ${topCampaign.distributed ? 'bg-error/5 border-error/20' : 'bg-primary-container/5 border-primary-container/20'}`}>
                <p className="text-[11px] leading-relaxed text-on-surface-variant">
                  <span className="font-bold text-on-surface">{topCampaign.label}</span> — {topCampaign.num_flows} flows from{' '}
                  {topCampaign.num_sources} sources targeting <span className="font-label-mono">{topCampaign.target}</span>{' '}
                  (source entropy {topCampaign.source_entropy}).
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Campaign list */}
        <div className="glass-panel p-6">
          <h4 className="text-label-caps text-on-surface-variant/80 mb-4 tracking-widest uppercase">Campaigns ({(report.campaigns || []).length})</h4>
          <div className="space-y-3 max-h-64 overflow-y-auto pr-1">
            {(report.campaigns || []).length === 0 && <p className="text-xs text-on-surface-variant italic">No campaigns aggregated.</p>}
            {(report.campaigns || []).map((c, i) => (
              <div key={i} className="p-3 bg-black/20 rounded-lg border border-white/5">
                <div className="flex justify-between items-start gap-2">
                  <span className="text-[11px] font-bold text-on-surface leading-tight">{c.label}</span>
                  <span className={`text-[9px] font-bold uppercase shrink-0 ${severityStyle(c.severity).text}`}>{c.severity}</span>
                </div>
                <p className="text-[10px] font-label-mono text-on-surface-variant mt-1">
                  {c.target} · {c.num_flows} flows · {c.num_sources} src
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
