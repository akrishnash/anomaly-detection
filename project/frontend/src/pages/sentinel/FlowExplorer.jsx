import React, { useMemo, useState } from 'react';
import { Icon, NoRunPanel, SeverityChip, severityStyle, formatBytes, formatDuration, flowBytes } from '../../sentinel/common';

function scoreColor(score) {
  if (score >= 0.8) return '#ffb4ab';
  if (score >= 0.5) return '#d1bcff';
  return '#00dbe9';
}

/** Three-step classification trace, rendered from the real backend trace. */
function TraceRow({ flow }) {
  const trace = flow.classification_trace || {};
  const s1 = trace.stage1_anomaly_detection;
  const s2 = trace.stage2_rule_engine;
  const s3 = trace.stage3_campaign_refinement;
  const isAnomaly = flow.prediction === 1;

  return (
    <td className="px-8 py-6" colSpan={10}>
      <div className="flex flex-col gap-5">
        <h4 className="text-label-caps text-primary tracking-widest uppercase">Classification Trace Logic</h4>
        <div className="flex items-stretch gap-4 flex-col xl:flex-row">
          {/* Stage 1 */}
          <div className={`glass-panel p-4 flex-1 ${isAnomaly ? 'border-primary/20' : ''}`}>
            <div className="text-label-caps text-on-surface-variant mb-2 uppercase tracking-widest">Stage 1 · Unsupervised Ensemble</div>
            <div className={`font-bold text-lg mb-2 ${isAnomaly ? 'text-error' : 'text-primary-container'}`}>
              {s1 ? s1.decision : isAnomaly ? 'ANOMALY' : 'NORMAL'}
            </div>
            {s1 && (
              <div className="space-y-2 text-[11px] font-label-mono text-on-surface-variant">
                {[
                  { label: 'ISOLATION FOREST', prob: s1.if_prob, raw: s1.if_raw },
                  { label: 'AUTOENCODER', prob: s1.ae_prob, raw: s1.ae_raw },
                ].map((h) => {
                  const fired = h.prob >= s1.threshold;
                  return (
                    <div key={h.label}>
                      <div className="flex justify-between">
                        <span>{h.label}</span>
                        <span className={fired ? 'text-error font-bold' : 'text-primary-container'}>
                          {h.prob?.toFixed(3)} {fired ? '≥' : '<'} {s1.threshold} {fired ? '· FIRED' : ''}
                        </span>
                      </div>
                      <div className="h-1 w-full bg-white/10 rounded-full overflow-hidden relative mt-1">
                        <div className="absolute top-0 bottom-0 w-0.5 bg-white/40 z-10" style={{ left: `${(s1.threshold || 0.5) * 100}%` }} />
                        <div className={`h-full ${fired ? 'bg-error' : 'bg-primary-container'}`} style={{ width: `${Math.min((h.prob || 0) * 100, 100)}%` }} />
                      </div>
                    </div>
                  );
                })}
                <div className="flex justify-between pt-1 border-t border-white/5">
                  <span>TRIGGERED BY</span>
                  <span className="text-on-surface font-bold">{s1.triggered_by}</span>
                </div>
              </div>
            )}
          </div>
          <Icon name="arrow_forward" className="text-on-surface-variant self-center hidden xl:block" />
          {/* Stage 2 */}
          <div className="glass-panel p-4 flex-1">
            <div className="text-label-caps text-on-surface-variant mb-2 uppercase tracking-widest">Stage 2 · Signature Rule Engine</div>
            {s2 ? (
              <>
                <div className="text-primary font-bold text-lg mb-2">
                  {s2.attack_type} <span className="text-xs font-label-mono text-on-surface-variant">({Math.round((s2.rule_confidence || 0) * 100)}% rule conf.)</span>
                </div>
                <ul className="space-y-1 text-[11px] text-on-surface-variant leading-relaxed">
                  {(s2.evidence || []).map((ev, i) => (
                    <li key={i} className="flex items-start gap-1.5">
                      <span className="text-primary-container mt-px">▸</span>
                      <span>{ev}</span>
                    </li>
                  ))}
                  {(!s2.evidence || s2.evidence.length === 0) && <li className="italic opacity-60">No signature evidence recorded.</li>}
                </ul>
              </>
            ) : (
              <div className="text-on-surface-variant/50 text-[11px] italic">
                Not run — Stage 1 classified this flow as benign, so no attack typing was needed.
              </div>
            )}
          </div>
          <Icon name="arrow_forward" className="text-on-surface-variant self-center hidden xl:block" />
          {/* Stage 3 */}
          <div className={`glass-panel p-4 flex-1 ${s3 ? 'bg-error/5 border-error/30' : ''}`}>
            <div className="text-label-caps text-on-surface-variant mb-2 uppercase tracking-widest">Stage 3 · Campaign Correlation</div>
            {s3 ? (
              <>
                <div className="text-error font-bold text-lg mb-2 flex items-center gap-2 flex-wrap">
                  <span className="text-on-surface-variant text-sm font-normal line-through">{s3.original_type}</span>
                  <Icon name="arrow_forward" className="text-[16px]" />
                  <span>{s3.refined_type}</span>
                </div>
                <p className="text-[11px] text-on-surface-variant leading-relaxed">{s3.reason}</p>
              </>
            ) : (
              <div className="text-on-surface-variant/50 text-[11px] italic">
                {isAnomaly
                  ? 'No cross-flow escalation — this flow was not correlated into a distributed campaign or scan sweep.'
                  : 'Not applicable for benign traffic.'}
              </div>
            )}
          </div>
        </div>
      </div>
    </td>
  );
}

export default function FlowExplorer({ lastRun, initialQuery, onNavigate }) {
  const [ipFilter, setIpFilter] = useState(initialQuery || '');
  const [sevFilter, setSevFilter] = useState('All');
  const [protoFilter, setProtoFilter] = useState('All');
  const [typeFilter, setTypeFilter] = useState('All');
  const [showBenign, setShowBenign] = useState(false);
  const [expanded, setExpanded] = useState(null);

  const report = lastRun;

  const allFlows = useMemo(() => {
    if (!report) return [];
    const rows = [...(report.anomalies || [])];
    if (showBenign) rows.push(...(report.benign || []));
    return rows;
  }, [report, showBenign]);

  const attackTypes = useMemo(
    () => [...new Set((report?.anomalies || []).map((f) => f.attack_type))].sort(),
    [report]
  );

  const flows = useMemo(() => {
    const q = ipFilter.trim().toLowerCase();
    return allFlows.filter((f) => {
      if (q && !(`${f.src_ip} ${f.dst_ip} ${f.attack_type} ${f.protocol}`.toLowerCase().includes(q))) return false;
      if (sevFilter !== 'All' && f.severity !== sevFilter) return false;
      if (protoFilter !== 'All' && String(f.protocol).toUpperCase() !== protoFilter) return false;
      if (typeFilter !== 'All' && f.attack_type !== typeFilter) return false;
      return true;
    });
  }, [allFlows, ipFilter, sevFilter, protoFilter, typeFilter]);

  function exportJson() {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'aegis_flow_report.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  if (!report) {
    return (
      <div className="space-y-6">
        <h2 className="font-geist text-headline-lg text-primary">Flow Explorer</h2>
        <NoRunPanel onNavigate={onNavigate} />
      </div>
    );
  }

  const avgEnsemble = report.anomalies?.length
    ? report.anomalies.reduce((a, f) => a + (f.ensemble_score || 0), 0) / report.anomalies.length
    : 0;
  const topType = (report.attacks || []).slice().sort((a, b) => b.value - a.value)[0];

  return (
    <div className="space-y-panel-gap">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h2 className="font-geist text-headline-lg text-primary">Flow Explorer</h2>
          <p className="text-body-md text-on-surface-variant max-w-xl mt-2">
            Inspect every analyzed flow and trace the ensemble scoring logic behind each verdict.
          </p>
        </div>
        <button
          onClick={exportJson}
          className="bg-surface-container border border-outline-variant/30 px-4 py-2 rounded-lg text-label-caps text-on-surface hover:border-primary-container/50 transition-all flex items-center gap-2 uppercase tracking-widest cursor-pointer"
        >
          <Icon name="file_download" className="text-[16px]" /> Export JSON
        </button>
      </div>

      {/* Filters */}
      <div className="glass-panel p-4 flex items-end gap-4 flex-wrap">
        <div className="flex flex-col gap-1.5 flex-1 min-w-52">
          <label className="text-label-caps text-on-surface-variant/60 uppercase tracking-widest">Search IP / Type</label>
          <div className="relative">
            <Icon name="lan" className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant/50 text-[16px]" />
            <input
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
              className="w-full bg-black/30 border border-outline-variant/30 rounded py-2 pl-9 pr-3 text-on-surface font-label-mono text-label-mono focus:ring-1 focus:ring-primary-container outline-none"
              placeholder="192.168.x.x or SYN Flood"
              type="text"
            />
          </div>
        </div>
        {[
          { label: 'Severity', value: sevFilter, set: setSevFilter, options: ['All', 'Critical', 'High', 'Medium', 'Low'] },
          { label: 'Protocol', value: protoFilter, set: setProtoFilter, options: ['All', 'TCP', 'UDP', 'ICMP'] },
          { label: 'Attack Type', value: typeFilter, set: setTypeFilter, options: ['All', ...attackTypes] },
        ].map((f) => (
          <div key={f.label} className="flex flex-col gap-1.5 w-48">
            <label className="text-label-caps text-on-surface-variant/60 uppercase tracking-widest">{f.label}</label>
            <select
              value={f.value}
              onChange={(e) => f.set(e.target.value)}
              className="bg-black/30 border border-outline-variant/30 rounded py-2 px-3 text-on-surface font-label-mono text-label-mono focus:ring-1 focus:ring-primary-container outline-none cursor-pointer"
            >
              {f.options.map((o) => <option key={o} className="bg-surface-container">{o}</option>)}
            </select>
          </div>
        ))}
        <button
          onClick={() => setShowBenign((v) => !v)}
          className={`h-10 px-4 rounded-lg border text-label-caps uppercase tracking-widest transition-all cursor-pointer ${
            showBenign ? 'border-primary-container/60 text-primary-container bg-primary-container/10' : 'border-outline-variant/30 text-on-surface-variant hover:bg-white/5'
          }`}
        >
          {showBenign ? 'Hiding nothing' : 'Anomalies only'}
        </button>
      </div>

      {/* Flow table */}
      <div className="glass-panel overflow-hidden border border-white/5">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[1100px]">
            <thead>
              <tr className="bg-surface-container-high/50 border-b border-white/5">
                {['SOURCE IP', 'DESTINATION', 'PROTO', 'DURATION', 'PACKETS', 'BYTES', 'ENSEMBLE SCORE', 'SEVERITY', 'ATTACK TYPE', ''].map((h) => (
                  <th key={h} className="px-4 py-4 text-label-caps text-on-surface-variant uppercase tracking-widest">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="font-label-mono text-label-mono divide-y divide-white/[0.03]">
              {flows.length === 0 && (
                <tr><td colSpan={10} className="px-4 py-10 text-center text-on-surface-variant/50 italic">No flows match the current filters.</td></tr>
              )}
              {flows.map((f) => {
                const isOpen = expanded === f.id;
                const score = f.ensemble_score || 0;
                const color = scoreColor(score);
                return (
                  <React.Fragment key={`${f.id}-${f.prediction}`}>
                    <tr
                      className="hover:bg-white/[0.04] transition-colors cursor-pointer group"
                      onClick={() => setExpanded(isOpen ? null : f.id)}
                    >
                      <td className="px-4 py-4 text-primary">{f.src_ip}</td>
                      <td className="px-4 py-4">{f.dst_ip}:{f.dst_port}</td>
                      <td className="px-4 py-4">{String(f.protocol).toUpperCase()}</td>
                      <td className="px-4 py-4">{formatDuration(f.flow_details?.flow_duration_s)}</td>
                      <td className="px-4 py-4">{(f.flow_details?.total_pkts || 0).toLocaleString()}</td>
                      <td className="px-4 py-4">{formatBytes(flowBytes(f))}</td>
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-2">
                          <div className="h-1 flex-1 min-w-16 bg-white/10 rounded-full overflow-hidden">
                            <div className="h-full" style={{ width: `${score * 100}%`, backgroundColor: color }} />
                          </div>
                          <span className="font-bold" style={{ color }}>{score.toFixed(2)}</span>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <span className={`flex items-center gap-1.5 ${severityStyle(f.severity).text}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${severityStyle(f.severity).dot} ${f.severity === 'Critical' ? 'pulse-critical' : ''}`} />
                          {(f.prediction === 1 ? f.severity : 'NORMAL').toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-4">{f.attack_type}</td>
                      <td className="px-4 py-4">
                        <Icon
                          name="expand_more"
                          className="text-on-surface-variant group-hover:text-primary transition-transform"
                          style={{ transform: isOpen ? 'rotate(180deg)' : 'none' }}
                        />
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className={`bg-black/40 border-l-2 ${f.prediction === 1 ? 'border-error' : 'border-primary-container'}`}>
                        <TraceRow flow={f} />
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-panel-gap">
        <div className="glass-panel p-4">
          <div className="text-label-caps text-on-surface-variant/60 mb-2 uppercase tracking-widest">Total Flows</div>
          <div className="font-geist text-headline-lg text-primary tracking-tight">{report.total_flows.toLocaleString()}</div>
          <div className="mt-2 text-[10px] text-on-surface-variant font-label-mono">SHOWING TOP {Math.min((report.anomalies || []).length + (showBenign ? (report.benign || []).length : 0), flows.length + 100)} SAMPLED ROWS</div>
        </div>
        <div className="glass-panel p-4 border-l-2 border-error">
          <div className="text-label-caps text-error/60 mb-2 uppercase tracking-widest">Anomalies Detected</div>
          <div className="font-geist text-headline-lg text-error tracking-tight">{report.anomalies_count.toLocaleString()}</div>
          <div className="mt-2 text-[10px] text-on-surface-variant font-label-mono">ENSEMBLE AVG: {avgEnsemble.toFixed(2)}</div>
        </div>
        <div className="glass-panel p-4">
          <div className="text-label-caps text-on-surface-variant/60 mb-2 uppercase tracking-widest">Threat Ratio</div>
          <div className="font-geist text-headline-lg text-on-surface tracking-tight">{report.threat_ratio}%</div>
          <div className="mt-2 text-[10px] text-primary font-label-mono">OF ANALYZED TRAFFIC</div>
        </div>
        <div className="glass-panel p-4 border-l-2 border-primary">
          <div className="text-label-caps text-primary/60 mb-2 uppercase tracking-widest">Dominant Vector</div>
          <div className="font-geist text-headline-md text-primary tracking-tight truncate">{topType?.name || 'None'}</div>
          <div className="mt-2 text-[10px] text-on-surface-variant font-label-mono">{topType ? `${topType.value} FLOWS` : 'NO ANOMALIES'}</div>
        </div>
      </div>
    </div>
  );
}
