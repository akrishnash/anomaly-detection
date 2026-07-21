import React, { useEffect, useRef, useState } from 'react';
import { Icon, formatCount, describeAttack, attackIcon } from '../../sentinel/common';
import { uploadFile, startOffline, getLogs } from '../../services/api';

const STAGES = [
  { icon: 'upload_file', label: 'Ingest File' },
  { icon: 'cyclone', label: 'Flow Generator' },
  { icon: 'database', label: 'Feature Extraction' },
  { icon: 'align_horizontal_center', label: 'Normalization' },
  { icon: 'forest', label: 'Stage 1: IF + AE', big: true },
  { icon: 'gavel', label: 'Ensemble Decision' },
  { icon: 'shield_locked', label: 'Stage 2: DDoS Engine' },
  { icon: 'summarize', label: 'Threat Report' },
];

const LOG_COLOR = { ERROR: 'text-error font-bold', WARNING: 'text-yellow-300', INFO: 'text-secondary' };

function StageCard({ stage, state }) {
  // state: 'idle' | 'active' | 'done'
  const done = state === 'done';
  const active = state === 'active';
  return (
    <div className={`flex flex-col items-center gap-3 relative z-10 ${stage.big ? 'scale-110' : ''}`}>
      <div
        className={`${stage.big ? 'w-36 h-36' : 'w-32 h-32'} glass-panel flex flex-col items-center justify-center p-4 text-center transition-all duration-300 ${
          active
            ? 'border-primary-container bg-primary-container/5 neon-glow-elevated'
            : done
              ? 'border-primary-container/40'
              : 'border-white/10 opacity-60'
        }`}
      >
        <Icon
          name={done ? 'check_circle' : stage.icon}
          className={`mb-2 ${stage.big ? 'text-4xl' : 'text-3xl'} ${active ? 'text-primary-container pulse-indicator rounded-full' : done ? 'text-primary-container' : 'text-on-surface-variant'}`}
        />
        <span className={`text-[10px] uppercase tracking-widest font-bold ${active || done ? 'text-primary-container' : 'text-on-surface-variant'}`}>
          {stage.label}
        </span>
      </div>
      <div className={`flex items-center gap-2 ${state === 'idle' ? 'opacity-40' : ''}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-primary-container pulse-indicator' : done ? 'bg-primary-container' : 'bg-on-surface-variant'}`} />
        <span className={`text-[10px] font-label-mono ${active || done ? 'text-primary-container' : 'text-on-surface-variant'}`}>
          {active ? 'PROCESSING' : done ? 'COMPLETE' : 'READY'}
        </span>
      </div>
    </div>
  );
}

export default function DetectionPipeline({ addToast, lastRun, onRunComplete, onNavigate, onInspectType, modelHealth }) {
  const [file, setFile] = useState(null);
  const [fileMeta, setFileMeta] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [running, setRunning] = useState(false);
  const [stageIdx, setStageIdx] = useState(lastRun ? STAGES.length : -1);
  const [elapsed, setElapsed] = useState(0);
  const [runSeconds, setRunSeconds] = useState(null);
  const [logs, setLogs] = useState([]);
  const fileInputRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => {
    let mounted = true;
    async function poll() {
      try {
        const data = await getLogs(12);
        if (mounted) setLogs([...data].reverse());
      } catch { /* backend offline */ }
    }
    poll();
    const id = setInterval(poll, 3000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  async function handleFileSelected(e) {
    const selected = e.target.files[0];
    if (!selected) return;
    setFile(selected);
    setFileMeta(null);
    try {
      setUploading(true);
      const meta = await uploadFile(selected);
      setFileMeta(meta);
      setStageIdx(-1);
      addToast(`File verified: ${meta.filename} (${meta.num_rows} records)`, 'success');
    } catch (err) {
      addToast(err.message || 'File verification failed.', 'error');
      setFile(null);
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  }

  async function handleRun() {
    if (!fileMeta || running) return;
    setRunning(true);
    setRunSeconds(null);
    setStageIdx(0);
    setElapsed(0);
    const startedAt = Date.now();

    // Elapsed clock + stage animation while the backend crunches the file.
    // Stages advance up to "Stage 2" and hold; the response completes the rail.
    timerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAt) / 1000));
      setStageIdx((idx) => Math.min(idx + 1, STAGES.length - 2));
    }, 700);

    try {
      const data = await startOffline(fileMeta.file_id, fileMeta.extension);
      clearInterval(timerRef.current);
      setStageIdx(STAGES.length);
      const secs = Math.max((Date.now() - startedAt) / 1000, 0.001);
      setRunSeconds(secs);
      onRunComplete(data);
      addToast(`Analysis complete — ${data.anomalies_count} anomalous flows flagged.`, data.anomalies_count > 0 ? 'error' : 'success');
      setFileMeta(null);
      setFile(null);
    } catch (err) {
      clearInterval(timerRef.current);
      setStageIdx(-1);
      addToast(err.message || 'Pipeline run failed.', 'error');
    } finally {
      setRunning(false);
    }
  }

  useEffect(() => () => clearInterval(timerRef.current), []);

  function stageState(i) {
    if (stageIdx >= STAGES.length) return 'done';
    if (i < stageIdx) return 'done';
    if (i === stageIdx && running) return 'active';
    return 'idle';
  }

  const report = lastRun;
  const dist = report?.score_distribution || [];
  const maxBin = Math.max(...dist.map((b) => b.normal + b.attack), 1);
  const healthAssets = Object.entries(modelHealth?.health_monitor || {});

  return (
    <div className="space-y-panel-gap">
      {/* Page header */}
      <div className="flex justify-between items-end relative z-10">
        <div>
          <h2 className="font-geist text-headline-lg text-primary tracking-tight">Detection Pipeline</h2>
          <p className="text-on-surface-variant mt-1 text-body-md">
            Two-stage unsupervised analysis: Isolation Forest ∪ Autoencoder, then DDoS signature typing.
          </p>
        </div>
        <div className="flex gap-4 items-center">
          {fileMeta && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-primary-container/10 border border-primary-container/30 rounded-lg">
              <Icon name="draft" className="text-primary-container text-[16px]" />
              <span className="font-label-mono text-label-mono text-primary-container">{fileMeta.filename}</span>
              <span className="text-[10px] text-on-surface-variant">{fileMeta.num_rows} rows</span>
            </div>
          )}
          <input ref={fileInputRef} type="file" accept=".csv,.xlsx,.xls,.parquet,.pcap,.pcapng" className="hidden" onChange={handleFileSelected} />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading || running}
            className="px-6 py-2 border border-white/10 hover:bg-white/5 transition-all rounded-lg font-bold text-sm disabled:opacity-40 cursor-pointer"
          >
            {uploading ? 'VERIFYING…' : 'SELECT FILE'}
          </button>
          <button
            onClick={handleRun}
            disabled={!fileMeta || running}
            className="px-6 py-2 bg-primary-container text-black font-bold rounded-lg text-sm transition-all hover:shadow-neon-cyan-strong active:scale-95 disabled:opacity-40 cursor-pointer"
          >
            {running ? 'ANALYZING…' : 'RUN PIPELINE'}
          </button>
        </div>
      </div>

      {/* Pipeline stage rail */}
      <section className="glass-panel p-8 relative overflow-x-auto">
        <div className="relative flex items-center justify-between min-w-[1200px] h-56 px-8">
          <div className="pipeline-line" />
          {STAGES.map((s, i) => <StageCard key={s.label} stage={s} state={stageState(i)} />)}
        </div>
      </section>

      {/* Plain-language verdict summary (for non-expert users) */}
      {report && (
        <section className={`glass-panel p-6 space-y-5 ${report.anomalies_count > 0 ? 'border-error/30' : 'border-primary-container/30'}`}>
          <div className="flex items-start gap-4">
            <Icon
              name={report.anomalies_count > 0 ? 'gpp_maybe' : 'verified_user'}
              className={`text-5xl ${report.anomalies_count > 0 ? 'text-error' : 'text-primary-container'}`}
            />
            <div>
              <h3 className={`font-geist text-headline-md ${report.anomalies_count > 0 ? 'text-error' : 'text-primary-container'}`}>
                {report.anomalies_count > 0 ? 'Attacks detected in this traffic' : 'No attacks detected'}
              </h3>
              <p className="text-body-md text-on-surface-variant mt-1 leading-relaxed max-w-3xl">
                {report.anomalies_count > 0 ? (
                  <>We analyzed <span className="text-on-surface font-bold">{report.total_flows.toLocaleString()}</span> traffic
                  flows. <span className="text-error font-bold">{report.anomalies_count.toLocaleString()}</span> of them
                  ({report.threat_ratio}%) look like attacks and{' '}
                  <span className="text-primary-container font-bold">{report.normal_count.toLocaleString()}</span> look normal.
                  Each attack found is explained below - click a card to inspect the affected flows.</>
                ) : (
                  <>We analyzed <span className="text-on-surface font-bold">{report.total_flows.toLocaleString()}</span> traffic
                  flows and all of them look like normal, everyday network activity.</>
                )}
              </p>
            </div>
          </div>

          {report.attack_details && report.attack_details.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {report.attack_details.map((d) => (
                <button
                  key={d.name}
                  onClick={() => onInspectType && onInspectType(d.name)}
                  className="text-left glass-panel p-4 space-y-2 border border-white/10 hover:border-error/50 transition-all cursor-pointer"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2 text-on-surface font-bold text-sm">
                      <Icon name={attackIcon(d.name)} className="text-error text-[18px]" />
                      {d.name}
                    </span>
                    <span className="px-2.5 py-1 rounded-full bg-error/15 border border-error/30 text-error font-bold text-xs whitespace-nowrap">
                      {d.flows.toLocaleString()} {d.flows === 1 ? 'flow' : 'flows'}
                    </span>
                  </div>
                  <p className="text-xs text-on-surface-variant leading-relaxed">{describeAttack(d.name)}</p>
                  {d.row_numbers && d.row_numbers.length > 0 && (
                    <div className="pt-1.5 border-t border-white/5">
                      <span className="text-[10px] text-on-surface-variant/60 uppercase font-label-mono tracking-widest">Found in file rows: </span>
                      <span className="text-[11px] text-primary-container font-label-mono">
                        {d.row_numbers.slice(0, 12).join(', ')}
                        {d.flows > 12 && ` ... and ${(d.flows - 12).toLocaleString()} more`}
                      </span>
                    </div>
                  )}
                </button>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Live processing + model assets */}
      <div className="grid grid-cols-12 gap-panel-gap">
        <div className="col-span-12 lg:col-span-8 glass-panel p-6 flex flex-col">
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-geist text-headline-md text-primary">Live Processing</h3>
            <div className="flex items-center gap-6">
              <div className="text-right">
                <p className="text-[10px] text-label-caps text-on-surface-variant uppercase tracking-widest">Throughput</p>
                <p className="font-label-mono text-xl text-primary-container">
                  {runSeconds && report ? `${formatCount(Math.round(report.total_flows / runSeconds))} flows/s` : running ? `${elapsed}s elapsed` : '—'}
                </p>
              </div>
              <div className="text-right">
                <p className="text-[10px] text-label-caps text-on-surface-variant uppercase tracking-widest">Flow Count</p>
                <p className="font-label-mono text-xl text-primary">{report ? report.total_flows.toLocaleString() : '0'}</p>
              </div>
              <div className="text-right">
                <p className="text-[10px] text-label-caps text-on-surface-variant uppercase tracking-widest">Anomalies</p>
                <p className="font-label-mono text-xl text-error">{report ? report.anomalies_count.toLocaleString() : '0'}</p>
              </div>
            </div>
          </div>

          {/* Ensemble score distribution histogram (real bins from the last run) */}
          <div className="flex-1 flex flex-col justify-end gap-3">
            <div className="h-24 flex items-end gap-1 px-2">
              {dist.length === 0 && (
                <div className="w-full text-center text-[10px] font-label-mono text-on-surface-variant/50 self-center">
                  ENSEMBLE SCORE DISTRIBUTION APPEARS HERE AFTER A RUN
                </div>
              )}
              {dist.map((b) => (
                <div key={b.bin} className="flex-1 flex flex-col justify-end gap-px h-full" title={`${b.bin}: ${b.normal} benign / ${b.attack} anomalous`}>
                  <div className="w-full bg-error/80 rounded-t-sm" style={{ height: `${(b.attack / maxBin) * 100}%` }} />
                  <div className="w-full bg-primary-container/50" style={{ height: `${(b.normal / maxBin) * 100}%` }} />
                </div>
              ))}
            </div>
            {dist.length > 0 && (
              <div className="flex justify-between text-[10px] font-label-mono text-on-surface-variant px-2">
                <span>SCORE 0.0</span>
                <span className="flex items-center gap-3">
                  <span className="flex items-center gap-1"><span className="w-2 h-2 bg-primary-container/50 inline-block rounded-sm" /> BENIGN</span>
                  <span className="flex items-center gap-1"><span className="w-2 h-2 bg-error/80 inline-block rounded-sm" /> ANOMALOUS</span>
                </span>
                <span>SCORE 1.0</span>
              </div>
            )}
            <div className="relative w-full h-1 bg-surface-container-highest rounded-full">
              <div
                className="absolute left-0 top-0 h-full bg-primary-container transition-all duration-500"
                style={{ width: `${stageIdx < 0 ? 0 : Math.min((stageIdx / STAGES.length) * 100, 100)}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] font-label-mono text-on-surface-variant">
              <span>{running ? `RUNNING · ${elapsed}s` : report ? 'ANALYSIS COMPLETE' : 'IDLE'}</span>
              {report && (
                <div className="flex gap-4">
                  <button onClick={() => onNavigate('explorer')} className="text-primary-container hover:underline cursor-pointer uppercase">
                    Inspect flows in explorer →
                  </button>
                  <button onClick={() => onNavigate('history')} className="text-primary hover:underline cursor-pointer uppercase font-bold">
                    View Intelligence History →
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Model asset health */}
        <div className="col-span-12 lg:col-span-4 glass-panel p-6">
          <h3 className="font-geist text-headline-md text-primary mb-6">Model Assets</h3>
          <div className="space-y-5">
            {healthAssets.length === 0 && <p className="text-xs text-on-surface-variant italic">Backend unreachable.</p>}
            {healthAssets.map(([asset, status]) => (
              <div key={asset}>
                <div className="flex justify-between mb-2">
                  <span className="text-label-caps text-on-surface-variant uppercase tracking-widest">{asset.replace('.pkl', '')}</span>
                  <span className={`font-label-mono text-label-mono ${status === 'Healthy' ? 'text-primary-container' : 'text-error'}`}>{status.toUpperCase()}</span>
                </div>
                <div className="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
                  <div className={`h-full ${status === 'Healthy' ? 'bg-primary-container w-full' : 'bg-error w-[8%]'}`} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Backend log terminal */}
      <section className="glass-panel overflow-hidden border-primary/20">
        <div className="bg-surface-container-highest/50 px-4 py-2 flex items-center justify-between border-b border-white/10">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-[#ff5f56]" />
            <div className="w-3 h-3 rounded-full bg-[#ffbd2e]" />
            <div className="w-3 h-3 rounded-full bg-[#27c93f]" />
            <span className="ml-4 font-label-mono text-xs text-on-surface-variant">aegis_backend.log</span>
          </div>
          <span className="font-label-mono text-[10px] text-primary-container animate-pulse">LIVE</span>
        </div>
        <div className="p-6 font-label-mono text-xs leading-relaxed text-on-surface/80 bg-[#0A0A0A] h-44 overflow-y-auto">
          {logs.map((l) => (
            <p key={l.id}>
              <span className="text-primary-container">[{(l.timestamp || '').split(' ')[1] || l.timestamp}]</span>{' '}
              <span className={LOG_COLOR[l.level] || 'text-secondary'}>{l.level}</span>{' '}
              {l.message}
            </p>
          ))}
        </div>
      </section>
    </div>
  );
}
