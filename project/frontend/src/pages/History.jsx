import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Download, 
  ShieldAlert, 
  ShieldCheck, 
  ChevronLeft, 
  ChevronRight, 
  Eye, 
  Calendar, 
  Tag, 
  FileText, 
  Clock, 
  Activity, 
  RefreshCw, 
  Layers, 
  FileCode,
  FileType,
  Filter,
  BarChart2
} from 'lucide-react';
import { getHistory, getShapExplanation, getHistoryStats, getExportUrl } from '../services/api';
import ShapDetails from '../components/ShapDetails';

export default function History() {
  const [records, setRecords] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [limit] = useState(15);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [mode, setMode] = useState('');
  const [prediction, setPrediction] = useState('');
  const [protocol, setProtocol] = useState('');
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('DESC');
  
  // History Stats & Capturing Time Interval State
  const [stats, setStats] = useState({
    total_records: 0,
    first_captured: 'N/A',
    latest_captured: 'N/A',
    interval_seconds: 0,
    formatted_duration: 'N/A',
    anomaly_count: 0,
    benign_count: 0,
    online_count: 0,
    offline_count: 0,
    is_running: false,
    sliding_window_sec: 30
  });

  // SHAP Modal State
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapData, setShapData] = useState(null);

  useEffect(() => {
    fetchHistory();
    fetchStats();
  }, [page, search, mode, prediction, protocol, sortBy, sortOrder]);

  // Polling for live status & history updates if sniffer is running
  useEffect(() => {
    let intervalId;
    if (stats.is_running) {
      intervalId = setInterval(() => {
        fetchHistory();
        fetchStats();
      }, 5000);
    }
    return () => clearInterval(intervalId);
  }, [stats.is_running, page, search, mode, prediction, protocol, sortBy, sortOrder]);

  async function fetchStats() {
    try {
      const data = await getHistoryStats(mode);
      setStats(data);
    } catch (err) {
      console.error('Error fetching history stats:', err);
    }
  }

  async function fetchHistory() {
    try {
      setLoading(true);
      const offset = (page - 1) * limit;
      const data = await getHistory({
        search,
        mode,
        prediction,
        protocol,
        limit,
        offset,
        sortBy,
        sortOrder
      });
      setRecords(data.records);
      setTotal(data.total);
    } catch (err) {
      console.error('Error fetching history:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleViewShap(record) {
    setSelectedRecord(record);
    setShapLoading(true);
    setShapData(null);
    try {
      const data = await getShapExplanation(record.id);
      setShapData(data);
    } catch (err) {
      console.error(err);
    } finally {
      setShapLoading(false);
    }
  }

  function toggleSort(field) {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'ASC' ? 'DESC' : 'ASC');
    } else {
      setSortBy(field);
      setSortOrder('DESC');
    }
    setPage(1);
  }

  const totalPages = Math.ceil(total / limit) || 1;
  const anomalyPct = stats.total_records > 0 ? ((stats.anomaly_count / stats.total_records) * 100).toFixed(1) : 0;

  return (
    <div className="space-y-8">
      {/* ─────────────────────────────────────────────────────────────────
          SECTION 1: INTELLIGENCE REPORT
      ───────────────────────────────────────────────────────────────── */}
      <section className="bg-cyber-card border border-cyber-cyan/30 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-cyber-cyan via-cyber-blue to-cyber-green" />
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-cyber-border/70 gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-cyber-cyan/10 border border-cyber-cyan/30 rounded-xl text-cyber-cyan shadow-[0_0_12px_rgba(6,182,212,0.2)]">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-xl font-bold font-mono text-white tracking-wider">INTELLIGENCE REPORT</h2>
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/30">
                  EXECUTIVE SUMMARY
                </span>
              </div>
              <p className="text-xs text-gray-400 font-mono mt-0.5">
                Real-time security intelligence telemetry and captured flow analysis
              </p>
            </div>
          </div>

          {/* Live Sniffer Status Indicator */}
          <div className="flex items-center space-x-4 bg-cyber-dark/60 border border-cyber-border px-4 py-2 rounded-xl">
            <div className="flex items-center space-x-2">
              <span className={`w-2.5 h-2.5 rounded-full ${stats.is_running ? 'bg-cyber-green animate-ping' : 'bg-gray-500'}`} />
              <span className="font-mono text-xs text-gray-300 font-bold">
                SNIFFER: {stats.is_running ? <span className="text-cyber-green">ACTIVE</span> : <span className="text-gray-400">IDLE</span>}
              </span>
            </div>
            <div className="h-4 w-px bg-cyber-border" />
            <button
              onClick={() => { fetchHistory(); fetchStats(); }}
              className="flex items-center space-x-1 text-xs text-cyber-cyan hover:text-white font-mono transition duration-200 cursor-pointer"
              title="Refresh intelligence metrics"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>REFRESH</span>
            </button>
          </div>
        </div>

        {/* Intelligence Report Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
          {/* Card 1: Capturing Time Interval */}
          <div className="bg-cyber-dark/70 border border-cyber-cyan/25 rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 font-mono text-xs mb-2">
              <span className="flex items-center space-x-1.5 text-cyber-cyan font-semibold">
                <Clock className="w-4 h-4" />
                <span>CAPTURING TIME INTERVAL</span>
              </span>
            </div>
            <div className="space-y-1 font-mono">
              <div className="text-lg font-bold text-white tracking-tight">
                {stats.formatted_duration}
              </div>
              <div className="text-[11px] text-gray-400 truncate">
                <span className="text-gray-500">START:</span> {stats.first_captured}
              </div>
              <div className="text-[11px] text-gray-400 truncate">
                <span className="text-gray-500">END:</span> {stats.latest_captured}
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-cyber-border/40 text-[10px] text-cyber-cyan font-mono flex items-center justify-between">
              <span>WINDOW: {stats.sliding_window_sec}s SLIDING</span>
              <span className="uppercase">{mode ? mode : 'ALL MODES'}</span>
            </div>
          </div>

          {/* Card 2: Total Captured Flows */}
          <div className="bg-cyber-dark/70 border border-cyber-border rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 font-mono text-xs mb-2">
              <span className="flex items-center space-x-1.5 text-gray-300 font-semibold">
                <Layers className="w-4 h-4 text-cyber-blue" />
                <span>CAPTURED FLOWS</span>
              </span>
              <span className="text-[10px] bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20 px-1.5 py-0.5 rounded">
                STORED
              </span>
            </div>
            <div className="font-mono">
              <div className="text-2xl font-bold text-white font-geist">{stats.total_records.toLocaleString()}</div>
              <div className="text-xs text-gray-400 mt-1 flex items-center space-x-2">
                <span className="text-cyber-cyan font-semibold">{stats.online_count} Live</span>
                <span>•</span>
                <span className="text-cyber-yellow font-semibold">{stats.offline_count} Batch</span>
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-cyber-border/40 text-[10px] text-gray-400 font-mono">
              INSPECTING CURRENT ACTIVE DATABASE
            </div>
          </div>

          {/* Card 3: Threat Ratio / Anomalies */}
          <div className="bg-cyber-dark/70 border border-cyber-border rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 font-mono text-xs mb-2">
              <span className="flex items-center space-x-1.5 text-cyber-red font-semibold">
                <ShieldAlert className="w-4 h-4 text-cyber-red" />
                <span>THREATS & ANOMALIES</span>
              </span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${stats.anomaly_count > 0 ? 'bg-cyber-red/10 text-cyber-red border border-cyber-red/20' : 'bg-cyber-green/10 text-cyber-green'}`}>
                {anomalyPct}%
              </span>
            </div>
            <div className="font-mono">
              <div className="text-2xl font-bold text-cyber-red font-geist">{stats.anomaly_count.toLocaleString()}</div>
              <div className="text-xs text-gray-400 mt-1">
                {stats.benign_count.toLocaleString()} Benign flows verified
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-cyber-border/40 text-[10px] text-gray-400 font-mono">
              DETECTION STAGE 1 & 2 ENGINES
            </div>
          </div>

          {/* Card 4: Threat Assessment Verdict */}
          <div className="bg-cyber-dark/70 border border-cyber-border rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 font-mono text-xs mb-2">
              <span className="flex items-center space-x-1.5 text-cyber-green font-semibold">
                <Activity className="w-4 h-4 text-cyber-green" />
                <span>THREAT ASSESSMENT</span>
              </span>
            </div>
            <div className="font-mono">
              <div className={`text-xl font-bold uppercase tracking-tight ${stats.anomaly_count > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                {stats.anomaly_count > 0 ? 'ATTACKS DETECTED' : 'NOMINAL / CLEAN'}
              </div>
              <p className="text-[11px] text-gray-400 mt-1 leading-snug">
                {stats.anomaly_count > 0
                  ? `${stats.anomaly_count} anomalous flow vector(s) captured across interval.`
                  : 'No critical security violations flagged in current interval.'}
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-cyber-border/40 text-[10px] text-cyber-green font-mono flex items-center justify-between">
              <span>STATUS: READY</span>
              <span>AEGIS-IDS</span>
            </div>
          </div>
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────────
          SECTION 2: HISTORY SECTION (LIVE CAPTURED DATA HISTORY)
          Placed JUST BELOW the Intelligence Report
      ───────────────────────────────────────────────────────────────── */}
      <section className="space-y-5 bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-xl relative">
        <div className="absolute top-0 left-0 w-[4px] h-full bg-cyber-cyan/60 rounded-l-2xl" />

        {/* Section Header with Title & Export Actions */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-4 border-b border-cyber-border gap-4">
          <div>
            <div className="flex items-center space-x-2.5">
              <div className="p-2 bg-cyber-cyan/10 border border-cyber-cyan/30 rounded-lg text-cyber-cyan">
                <Calendar className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-xl font-bold font-mono text-white tracking-wider">
                  LIVE CAPTURED DATA HISTORY
                </h3>
                <p className="text-xs text-gray-400 font-mono mt-0.5">
                  Inspect captured network traffic history with live time interval metrics and multi-format exports
                </p>
              </div>
            </div>
          </div>

          {/* Export Toolbar: CSV, PDF, JSON, XML, TXT */}
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            {/* Export CSV */}
            <a
              href={getExportUrl('csv', { mode, search, prediction, protocol })}
              download
              className="flex items-center space-x-1.5 px-3 py-2 bg-gray-800 hover:bg-gray-700 text-white font-bold border border-gray-700 rounded-xl hover:border-cyber-cyan/40 active:scale-95 transition-all duration-200 cursor-pointer shadow-sm"
              title="Export captured history in CSV format"
            >
              <Download className="w-3.5 h-3.5 text-cyber-cyan" />
              <span>CSV</span>
            </a>

            {/* Download PDF */}
            <a
              href={getExportUrl('pdf', { mode, search, prediction, protocol })}
              download
              className="flex items-center space-x-1.5 px-3 py-2 bg-cyber-cyan/10 hover:bg-cyber-cyan/20 text-cyber-cyan font-bold border border-cyber-cyan/35 rounded-xl shadow-[0_0_8px_rgba(6,182,212,0.15)] active:scale-95 transition-all duration-200 cursor-pointer"
              title="Download executive PDF history report"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>PDF</span>
            </a>

            {/* Export JSON */}
            <a
              href={getExportUrl('json', { mode, search, prediction, protocol })}
              download
              className="flex items-center space-x-1.5 px-3 py-2 bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue font-bold border border-cyber-blue/30 rounded-xl shadow-[0_0_8px_rgba(59,130,246,0.1)] active:scale-95 transition-all duration-200 cursor-pointer"
              title="Export captured telemetry in JSON format"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>JSON</span>
            </a>

            {/* Export XML */}
            <a
              href={getExportUrl('xml', { mode, search, prediction, protocol })}
              download
              className="flex items-center space-x-1.5 px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 font-bold border border-purple-500/30 rounded-xl shadow-[0_0_8px_rgba(168,85,247,0.1)] active:scale-95 transition-all duration-200 cursor-pointer"
              title="Export captured telemetry in XML format"
            >
              <FileType className="w-3.5 h-3.5" />
              <span>XML</span>
            </a>

            {/* Export TXT */}
            <a
              href={getExportUrl('txt', { mode, search, prediction, protocol })}
              download
              className="flex items-center space-x-1.5 px-3 py-2 bg-cyber-green/10 hover:bg-cyber-green/20 text-cyber-green font-bold border border-cyber-green/30 rounded-xl shadow-[0_0_8px_rgba(34,197,94,0.1)] active:scale-95 transition-all duration-200 cursor-pointer"
              title="Export text log digest"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>TXT</span>
            </a>
          </div>
        </div>

        {/* Capturing Time Interval Banner Badge */}
        <div className="bg-cyber-dark/80 border border-cyber-border/80 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between font-mono text-xs gap-3 shadow-inner">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center space-x-2 text-cyber-cyan font-bold">
              <Clock className="w-4 h-4 shrink-0" />
              <span>CAPTURING TIME INTERVAL:</span>
            </div>
            <div className="flex items-center space-x-2 bg-gray-900 border border-cyber-border px-3 py-1 rounded-lg">
              <span className="text-gray-400 text-[11px]">START:</span>
              <span className="text-white font-bold">{stats.first_captured}</span>
              <span className="text-cyber-cyan font-bold">➔</span>
              <span className="text-gray-400 text-[11px]">END:</span>
              <span className="text-white font-bold">{stats.latest_captured}</span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-1.5 text-gray-300">
              <span className="text-gray-500">DURATION:</span>
              <span className="text-cyber-cyan font-bold bg-cyber-cyan/10 border border-cyber-cyan/20 px-2 py-0.5 rounded">
                {stats.formatted_duration}
              </span>
            </div>
            <div className="h-4 w-px bg-cyber-border hidden md:block" />
            <div className="flex items-center space-x-1.5 text-gray-300">
              <span className="text-gray-500">MATCHING RECORDS:</span>
              <span className="text-white font-bold bg-gray-800 border border-gray-700 px-2 py-0.5 rounded">
                {total.toLocaleString()}
              </span>
            </div>
          </div>
        </div>

        {/* Filters Section */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 bg-cyber-card border border-cyber-border p-4 rounded-xl shadow-lg font-mono text-xs">
          {/* Mode Selector Tabs */}
          <div className="col-span-1 sm:col-span-2 lg:col-span-1 flex bg-cyber-dark p-1 rounded-lg border border-cyber-border">
            <button
              onClick={() => { setMode(''); setPage(1); }}
              className={`flex-1 py-1.5 px-2 rounded text-[11px] font-bold transition-all cursor-pointer ${
                mode === '' ? 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/30' : 'text-gray-400 hover:text-white'
              }`}
            >
              ALL
            </button>
            <button
              onClick={() => { setMode('Online'); setPage(1); }}
              className={`flex-1 py-1.5 px-2 rounded text-[11px] font-bold transition-all cursor-pointer ${
                mode === 'Online' ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30' : 'text-gray-400 hover:text-white'
              }`}
            >
              LIVE (ONLINE)
            </button>
            <button
              onClick={() => { setMode('Offline'); setPage(1); }}
              className={`flex-1 py-1.5 px-2 rounded text-[11px] font-bold transition-all cursor-pointer ${
                mode === 'Offline' ? 'bg-cyber-yellow/20 text-cyber-yellow border border-cyber-yellow/30' : 'text-gray-400 hover:text-white'
              }`}
            >
              OFFLINE
            </button>
          </div>

          {/* Search */}
          <div className="relative">
            <span className="absolute inset-y-0 left-0 flex items-center pl-3">
              <Search className="w-4 h-4 text-gray-500" />
            </span>
            <input
              type="text"
              placeholder="Search IPs or attacks..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="w-full bg-cyber-dark border border-cyber-border rounded-lg pl-9 pr-4 py-2 text-white focus:outline-none focus:border-cyber-cyan transition-all"
            />
          </div>

          {/* Classification Filter */}
          <select
            value={prediction}
            onChange={(e) => { setPrediction(e.target.value); setPage(1); }}
            className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan cursor-pointer"
          >
            <option value="">All Classifications</option>
            <option value="0">Benign (Normal)</option>
            <option value="1">Anomaly (Attack)</option>
          </select>

          {/* Protocol Filter */}
          <select
            value={protocol}
            onChange={(e) => { setProtocol(e.target.value); setPage(1); }}
            className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan cursor-pointer"
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="Other">Other</option>
          </select>

          {/* Reset Filters */}
          <button
            onClick={() => {
              setSearch('');
              setMode('');
              setPrediction('');
              setProtocol('');
              setPage(1);
            }}
            className="bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white border border-gray-700 rounded-lg px-3 py-2 flex items-center justify-center space-x-1.5 transition-all cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>RESET FILTERS</span>
          </button>
        </div>

        {/* History Data Table Grid */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-cyber-dark text-gray-400 border-b border-cyber-border">
                <tr>
                  {[
                    { field: 'id', label: 'ID' },
                    { field: 'timestamp', label: 'TIMESTAMP' },
                    { field: 'mode', label: 'MODE' },
                    { field: 'file_row_number', label: 'FILE ROW / FLOW' },
                    { field: 'src_ip', label: 'SOURCE IP' },
                    { field: 'dst_ip', label: 'DESTINATION IP' },
                    { field: 'protocol', label: 'PROTO' },
                    { field: 'dst_port', label: 'PORT' },
                    { field: 'prediction', label: 'CLASS' },
                    { field: 'confidence', label: 'CONFIDENCE' },
                    { field: 'attack_type', label: 'ATTACK CATEGORY' },
                  ].map((col) => (
                    <th
                      key={col.field}
                      onClick={() => toggleSort(col.field)}
                      className="p-4 cursor-pointer hover:bg-gray-800/50 hover:text-white transition-colors duration-200 select-none text-center"
                    >
                      <div className="flex items-center justify-center space-x-1">
                        <span>{col.label}</span>
                        {sortBy === col.field && (
                          <span className="text-cyber-cyan">{sortOrder === 'ASC' ? '▲' : '▼'}</span>
                        )}
                      </div>
                    </th>
                  ))}
                  <th className="p-4 text-center">EXPLAIN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border">
                {loading ? (
                  <tr>
                    <td colSpan="12" className="p-12 text-center text-cyber-cyan animate-pulse">
                      FETCHING INCIDENT HISTORY DATA...
                    </td>
                  </tr>
                ) : records.length === 0 ? (
                  <tr>
                    <td colSpan="12" className="p-12 text-center text-gray-500 italic">
                      No matching live captured threat records found in history.
                    </td>
                  </tr>
                ) : (
                  records.map((record) => {
                    const isAttack = record.prediction === 1;
                    return (
                      <tr
                        key={record.id}
                        className={`hover:bg-gray-850/50 transition-colors duration-150 ${
                          isAttack ? 'bg-cyber-red/5' : 'bg-transparent'
                        }`}
                      >
                        <td className="p-4 text-center text-gray-500">{record.id}</td>
                        <td className="p-4 text-center text-gray-300 font-semibold">{record.timestamp}</td>
                        <td className="p-4 text-center">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            record.mode === 'Online' 
                              ? 'bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20' 
                              : 'bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20'
                          }`}>
                            {record.mode}
                          </span>
                        </td>
                        <td className="p-4 text-center text-cyber-cyan font-semibold">
                          {record.file_row_number ? `#${record.file_row_number}` : '—'}
                        </td>
                        <td className="p-4 text-center font-bold text-gray-200">{record.src_ip}</td>
                        <td className="p-4 text-center font-bold text-gray-200">{record.dst_ip}</td>
                        <td className="p-4 text-center">
                          <span className="bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{record.protocol}</span>
                        </td>
                        <td className="p-4 text-center text-gray-400 font-semibold">{record.dst_port}</td>
                        <td className="p-4 text-center">
                          {isAttack ? (
                            <span className="flex items-center justify-center space-x-1 text-cyber-red bg-cyber-red/10 border border-cyber-red/20 px-2 py-0.5 rounded-full font-bold shadow-[0_0_8px_rgba(239,68,68,0.08)]">
                              <ShieldAlert className="w-3.5 h-3.5" />
                              <span>ATTACK</span>
                            </span>
                          ) : (
                            <span className="flex items-center justify-center space-x-1 text-cyber-green bg-cyber-green/10 border border-cyber-green/20 px-2 py-0.5 rounded-full font-bold">
                              <ShieldCheck className="w-3.5 h-3.5" />
                              <span>NORMAL</span>
                            </span>
                          )}
                        </td>
                        <td className="p-4 text-center font-semibold text-gray-300">
                          {record.confidence ? record.confidence.toFixed(2) : '0.00'}%
                        </td>
                        <td className="p-4 text-center text-gray-200">
                          {isAttack ? (
                            <span className="text-cyber-yellow font-bold">{record.attack_type}</span>
                          ) : (
                            <span className="text-gray-500">—</span>
                          )}
                        </td>
                        <td className="p-4 text-center">
                          {isAttack ? (
                            <button
                              onClick={() => handleViewShap(record)}
                              className="p-1 bg-cyber-cyan/10 text-cyber-cyan hover:bg-cyber-cyan hover:text-cyber-dark border border-cyber-cyan/30 hover:border-cyber-cyan rounded transition-all duration-300 shadow-[0_0_6px_rgba(6,182,212,0.05)] cursor-pointer"
                              title="Inspect SHAP explanation"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="flex items-center justify-between border-t border-cyber-border bg-cyber-dark/40 px-6 py-4 font-mono">
            <span className="text-xs text-gray-500">
              PAGE {page} OF {totalPages} ({total} TOTAL RECORDS)
            </span>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setPage(Math.max(page - 1, 1))}
                disabled={page === 1}
                className="p-1.5 bg-gray-800 hover:bg-gray-700 text-white rounded-lg border border-gray-700 disabled:opacity-30 disabled:pointer-events-none active:scale-95 transition-all cursor-pointer"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage(Math.min(page + 1, totalPages))}
                disabled={page === totalPages}
                className="p-1.5 bg-gray-800 hover:bg-gray-700 text-white rounded-lg border border-gray-700 disabled:opacity-30 disabled:pointer-events-none active:scale-95 transition-all cursor-pointer"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────────
          SHAP EXPLAINABILITY MODAL DRAWER
      ───────────────────────────────────────────────────────────────── */}
      {selectedRecord && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end transition-opacity">
          <div className="w-full max-w-2xl bg-cyber-card border-l border-cyber-border h-full shadow-2xl flex flex-col p-6 relative overflow-y-auto animate-scanline-pane">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4 mb-6">
              <div className="flex items-center space-x-2">
                <Tag className="w-5 h-5 text-cyber-yellow" />
                <h3 className="text-lg font-bold font-mono text-white">
                  INCIDENT INTERPRETATION [ID: {selectedRecord.id}]
                </h3>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-3 py-1.5 bg-gray-800 hover:bg-cyber-red/20 hover:text-cyber-red border border-gray-750 hover:border-cyber-red/30 rounded-lg text-xs font-mono text-gray-400 transition-all duration-300 cursor-pointer"
              >
                CLOSE
              </button>
            </div>

            {shapLoading ? (
              <div className="flex-1 flex items-center justify-center font-mono text-cyber-cyan animate-pulse">
                COMPUTING local TreeSHAP ATTRIBUTIONS...
              </div>
            ) : (
              shapData && (
                <div className="space-y-6">
                  {/* Flow Stats Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 bg-cyber-dark/40 border border-cyber-border p-4 rounded-xl text-center">
                    <div>
                      <div className="text-[10px] text-gray-500">SOURCE IP</div>
                      <div className="text-sm font-bold text-white">{selectedRecord.src_ip}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-500">DESTINATION IP</div>
                      <div className="text-sm font-bold text-white">{selectedRecord.dst_ip}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-500">CONFIDENCE</div>
                      <div className="text-sm font-bold text-cyber-red">{selectedRecord.confidence?.toFixed(2)}%</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-500">ISOLATION FOREST SCORE</div>
                      <div className="text-sm font-bold text-cyber-yellow">{selectedRecord.if_score}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-500">FILE ROW / FLOW</div>
                      <div className="text-sm font-bold text-cyber-cyan">{selectedRecord.file_row_number ? `#${selectedRecord.file_row_number}` : '—'}</div>
                    </div>
                  </div>

                  {/* SHAP Explanations Sub-component */}
                  <ShapDetails 
                    explanation={shapData.shap_explanation} 
                    textExplanation={shapData.text_explanation}
                    attackType={shapData.attack_type}
                  />
                </div>
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
}
