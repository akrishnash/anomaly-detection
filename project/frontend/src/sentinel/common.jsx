import React from 'react';

/** Material Symbols ligature icon (font is bundled locally). */
export function Icon({ name, className = '', fill = false, style = {} }) {
  return (
    <span
      className={`material-symbols-outlined ${className}`}
      style={fill ? { fontVariationSettings: "'FILL' 1", ...style } : style}
    >
      {name}
    </span>
  );
}

/* Severity → design-token color. Critical/High use the error family,
   Medium the cyan accent, Low the muted variant (per DESIGN.md status rules). */
export const SEVERITY_STYLE = {
  Critical: { text: 'text-error', bg: 'bg-error/10', border: 'border-error/20', dot: 'bg-error', hex: '#ffb4ab', pulse: true },
  High: { text: 'text-orange-300', bg: 'bg-orange-400/10', border: 'border-orange-400/20', dot: 'bg-orange-300', hex: '#fdba74', pulse: false },
  Medium: { text: 'text-primary-container', bg: 'bg-primary-container/10', border: 'border-primary-container/20', dot: 'bg-primary-container', hex: '#00f0ff', pulse: false },
  Low: { text: 'text-on-surface-variant', bg: 'bg-white/5', border: 'border-white/10', dot: 'bg-on-surface-variant', hex: '#b9cacb', pulse: false },
};

export function severityStyle(sev) {
  return SEVERITY_STYLE[sev] || SEVERITY_STYLE.Low;
}

export function SeverityChip({ severity }) {
  const s = severityStyle(severity);
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${s.text} ${s.bg} ${s.border} uppercase tracking-wider`}>
      {severity}
    </span>
  );
}

/** Icon per DDoS/attack subtype for the classification cards. */
export function attackIcon(name) {
  const n = (name || '').toLowerCase();
  if (n.includes('syn')) return 'warning';
  if (n.includes('udp')) return 'waves';
  if (n.includes('icmp')) return 'notification_important';
  if (n.includes('amplification') || n.includes('dns')) return 'dns';
  if (n.includes('http')) return 'http';
  if (n.includes('slowloris')) return 'hourglass_top';
  if (n.includes('scan') || n.includes('recon')) return 'radar';
  if (n.includes('brute')) return 'key';
  if (n.includes('exfiltration')) return 'upload_file';
  if (n.includes('volumetric') || n.includes('flood')) return 'speed';
  if (n.includes('unknown')) return 'help';
  return 'bug_report';
}

export function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(2)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${Math.round(b)} B`;
}

export function formatCount(n) {
  const v = Number(n) || 0;
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
  return `${v}`;
}

/** Flow duration for table cells. */
export function formatDuration(sec) {
  const s = Number(sec) || 0;
  if (s >= 1) return `${s.toFixed(1)}s`;
  return `${Math.round(s * 1000)}ms`;
}

export function flowBytes(flow) {
  const fd = flow.flow_details || {};
  return (Number(fd.fwd_bytes) || 0) + (Number(fd.bwd_bytes) || 0);
}

/** Empty state shown when no analysis has been run yet. */
export function NoRunPanel({ onNavigate }) {
  return (
    <div className="glass-panel p-16 flex flex-col items-center justify-center text-center gap-4">
      <Icon name="query_stats" className="text-primary-container/40" style={{ fontSize: '56px' }} />
      <h3 className="font-geist text-headline-md text-on-surface">No analysis data yet</h3>
      <p className="text-body-md text-on-surface-variant max-w-md">
        Run a capture file through the detection pipeline to populate this screen
        with live classification results.
      </p>
      {onNavigate && (
        <button
          onClick={() => onNavigate('pipeline')}
          className="mt-2 px-6 py-2 bg-primary-container text-black font-bold rounded-lg text-sm hover:shadow-neon-cyan-strong transition-all cursor-pointer"
        >
          OPEN DETECTION PIPELINE
        </button>
      )}
    </div>
  );
}
