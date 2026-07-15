import React, { useState } from 'react';
import { Upload, HardDrive, Play, Activity, AlertTriangle, ShieldCheck, ShieldAlert, Award, ChevronDown, ChevronUp, Tag } from 'lucide-react';
import { 
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, Legend,
  PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';
import { uploadFile, startOffline } from '../services/api';
import ShapDetails from '../components/ShapDetails';

export default function OfflineDetection({ addToast }) {
  const COLOR_CYAN = '#06b6d4';
  const COLOR_GREEN = '#10b981';
  const COLOR_RED = '#ef4444';
  const COLOR_YELLOW = '#f59e0b';
  const COLOR_BLUE = '#3b82f6';
  
  const PROTOCOL_COLORS = [COLOR_CYAN, COLOR_BLUE, COLOR_YELLOW];

  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [fileMeta, setFileMeta] = useState(null);
  
  // Pipeline Progress State
  const [analyzing, setAnalyzing] = useState(false);
  const [progressStage, setProgressStage] = useState('');
  const [progressValue, setProgressValue] = useState(0);
  
  // Predictions Results
  const [results, setResults] = useState(null);
  
  // Selected Anomaly for SHAP detail
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);
  const [showType, setShowType] = useState('anomalies');

  const handleShowTypeChange = (type) => {
    setShowType(type);
    setExpandedRow(null);
  };

  function handleFileChange(e) {
    const selected = e.target.files[0];
    if (selected) {
      setFile(selected);
      setFileMeta(null);
      setResults(null);
      setSelectedAnomaly(null);
    }
  }

  async function handleUpload() {
    if (!file) return;
    try {
      setUploading(true);
      const data = await uploadFile(file);
      setFileMeta(data);
      addToast('File uploaded and verified successfully.', 'success');
    } catch (err) {
      addToast(err.message || 'File verification failed.', 'error');
    } finally {
      setUploading(false);
    }
  }

  async function handleStartDetection() {
    if (!fileMeta) return;
    try {
      setAnalyzing(true);
      setResults(null);
      setSelectedAnomaly(null);
      
      // Simulate preprocessing progress (UI aesthetic requirement)
      setProgressStage('Preprocessing features, cleansing datasets & imputing missing values...');
      setProgressValue(15);
      await delay(600);
      setProgressValue(45);
      await delay(400);
      
      setProgressStage('Extracting CICFlowMeter-like flow representations...');
      setProgressValue(65);
      await delay(500);
      
      setProgressStage('Evaluating unsupervised Isolation Forest anomaly scoring...');
      setProgressValue(80);
      await delay(600);
      
      setProgressStage('Scoring flows with unsupervised ensemble and DDoS rule engine...');
      setProgressValue(95);
      
      // Run actual inference request
      const data = await startOffline(fileMeta.file_id, fileMeta.extension);
      
      setProgressValue(100);
      await delay(300);
      
      setResults(data);
      addToast(`offline analysis completed. Flagged ${data.anomalies_count} malicious flows.`, 'success');
    } catch (err) {
      addToast(err.message || 'Pipeline analysis execution failed.', 'error');
    } finally {
      setAnalyzing(false);
    }
  }

  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center space-x-2 text-white font-mono border-b border-cyber-border pb-3 mb-6">
        <HardDrive className="w-5 h-5 text-cyber-cyan" />
        <h2 className="text-xl font-bold tracking-wider">OFFLINE ANOMALY DETECTION ENGINE</h2>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Container */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-xl relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-cyber-cyan/30" />
            <h3 className="text-sm font-bold font-mono text-white mb-4">INGEST DATASET SOURCE</h3>
            
            <div className="space-y-4">
              {/* Drag Drop Area */}
              <label className="flex flex-col items-center justify-center border-2 border-dashed border-cyber-border hover:border-cyber-cyan/50 bg-cyber-dark/40 hover:bg-cyber-dark/80 rounded-xl p-6 cursor-pointer group transition-all duration-300">
                <Upload className="w-10 h-10 text-gray-500 group-hover:text-cyber-cyan group-hover:scale-110 transition-all duration-300" />
                <span className="text-xs text-gray-400 mt-3 font-mono text-center">
                  {file ? file.name : 'CLICK OR DRAG FILE TO INGEST'}
                </span>
                <span className="text-[10px] text-gray-500 font-mono mt-1">SUPPORTED: CSV, XLSX, XLS, PCAP, PCAPNG</span>
                <input type="file" onChange={handleFileChange} className="hidden" accept=".csv,.xlsx,.xls,.pcap,.pcapng" />
              </label>

              {file && !fileMeta && (
                <button
                  onClick={handleUpload}
                  disabled={uploading}
                  className="w-full py-2.5 bg-cyber-cyan hover:bg-cyber-cyan/85 text-cyber-dark font-bold font-mono rounded-lg transition-all duration-300 cursor-pointer disabled:opacity-50"
                >
                  {uploading ? 'VERIFYING FILE SCHEMA...' : 'VERIFY & UPLOAD'}
                </button>
              )}
            </div>
          </div>

          {/* Uploaded File Info Card */}
          {fileMeta && (
            <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4 shadow-xl font-mono text-xs relative overflow-hidden animate-scanline-pane">
              <h4 className="text-xs font-bold text-white uppercase border-b border-cyber-border pb-2">DATA STRUCTURE METADATA</h4>
              <div className="space-y-2">
                <div className="flex justify-between"><span className="text-gray-500">FILENAME:</span><span className="text-white font-semibold break-all">{fileMeta.filename}</span></div>
                <div className="flex justify-between"><span className="text-gray-500">FILE SIZE:</span><span className="text-cyber-cyan font-bold">{fileMeta.size_mb} MB</span></div>
                <div className="flex justify-between"><span className="text-gray-500">RECORD COUNT:</span><span className="text-white">{fileMeta.num_rows}</span></div>
                <div className="flex justify-between"><span className="text-gray-500">FEATURE COLS:</span><span className="text-white">{fileMeta.num_cols}</span></div>
                <div className="flex justify-between">
                  <span className="text-gray-500">FORMAT INTEGRITY:</span>
                  <span className="text-cyber-green flex items-center space-x-1 font-bold">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>VALIDATED</span>
                  </span>
                </div>
              </div>

              {!analyzing && (
                <button
                  onClick={handleStartDetection}
                  className="w-full flex items-center justify-center space-x-2 py-3 bg-cyber-green hover:bg-cyber-green/85 text-cyber-dark font-bold rounded-lg border border-cyber-green shadow-glow-green active:scale-95 transition-all duration-300 cursor-pointer"
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>START DETECTION RUN</span>
                </button>
              )}
            </div>
          )}
        </div>

        {/* Preview / Results Area */}
        <div className="lg:col-span-2 space-y-6">
          {/* Diagnostic Progress Loading Bar */}
          {analyzing && (
            <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4 shadow-xl font-mono">
              <div className="flex justify-between items-center text-xs">
                <span className="text-cyber-cyan animate-pulse flex items-center space-x-1.5">
                  <Activity className="w-4 h-4 text-cyber-cyan animate-spin" />
                  <span>{progressStage}</span>
                </span>
                <span className="text-white font-bold">{progressValue}%</span>
              </div>
              <div className="w-full h-2.5 bg-gray-800 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyber-cyan shadow-glow-cyan transition-all duration-300"
                  style={{ width: `${progressValue}%` }}
                />
              </div>
            </div>
          )}

          {/* Results Summary Overview */}
          {results && (
            <div className="space-y-6 animate-scanline-pane">
              {/* Prediction metrics overview */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 text-center font-mono">
                  <div className="text-[10px] text-gray-500">ANALYZED TRAFFIC FLOWS</div>
                  <div className="text-2xl font-bold text-white mt-1">{results.total_flows}</div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 text-center font-mono">
                  <div className="text-[10px] text-gray-500">BENIGN TRAFFIC</div>
                  <div className="text-2xl font-bold text-cyber-green mt-1">{results.normal_count}</div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 text-center font-mono">
                  <div className="text-[10px] text-gray-500">IDENTIFIED ANOMALIES</div>
                  <div className="text-2xl font-bold text-cyber-red mt-1">{results.anomalies_count}</div>
                </div>
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 text-center font-mono">
                  <div className="text-[10px] text-gray-500">THREAT RATIO</div>
                  <div className="text-2xl font-bold text-cyber-yellow mt-1">{results.threat_ratio}%</div>
                </div>
              </div>

              {/* Classification report (Ground Truth) */}
              {results.classification_report && Object.keys(results.classification_report).length > 0 && (
                <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4 shadow-xl">
                  <div className="flex items-center space-x-2 text-white font-mono text-sm font-bold border-b border-cyber-border pb-2">
                    <Award className="w-4 h-4 text-cyber-cyan" />
                    <span>CLASSIFICATION PERFORMANCE METRICS (VS LABELS)</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-center">
                    <div className="bg-cyber-dark/40 p-3 rounded-lg border border-cyber-border">
                      <div className="text-[10px] text-gray-500">ACCURACY</div>
                      <div className="text-lg font-bold text-white">{results.classification_report.accuracy}%</div>
                    </div>
                    <div className="bg-cyber-dark/40 p-3 rounded-lg border border-cyber-border">
                      <div className="text-[10px] text-gray-500">PRECISION</div>
                      <div className="text-lg font-bold text-white">{results.classification_report.precision}%</div>
                    </div>
                    <div className="bg-cyber-dark/40 p-3 rounded-lg border border-cyber-border">
                      <div className="text-[10px] text-gray-500">RECALL (DETECTION RATE)</div>
                      <div className="text-lg font-bold text-white">{results.classification_report.recall}%</div>
                    </div>
                    <div className="bg-cyber-dark/40 p-3 rounded-lg border border-cyber-border">
                      <div className="text-[10px] text-gray-500">F1 SCORE</div>
                      <div className="text-lg font-bold text-white">{results.classification_report.f1_score}%</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Charts Visualizations Row */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Timeline Chart */}
                <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl space-y-4">
                  <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2 uppercase">
                    Detection Classifications Timeline
                  </h3>
                  <div className="h-60">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={results.timeline || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <XAxis dataKey="time" stroke="#4b5563" fontSize={9} tickLine={false} />
                        <YAxis stroke="#4b5563" fontSize={9} tickLine={false} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: 11, fontFamily: 'monospace' }}
                        />
                        <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'monospace' }} />
                        <Line type="monotone" dataKey="normal" stroke={COLOR_GREEN} strokeWidth={2} name="Benign Traffic" dot={{ r: 2 }} activeDot={{ r: 4 }} />
                        <Line type="monotone" dataKey="attacks" stroke={COLOR_RED} strokeWidth={2} name="Malicious Anomaly" dot={{ r: 2 }} activeDot={{ r: 4 }} />
                        <Line type="monotone" dataKey="detection_rate" stroke={COLOR_CYAN} strokeWidth={1.5} strokeDasharray="3 3" name="Threat Ratio (%)" dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Sub-distributions (Protocols and Attack Breakdown) */}
                <div className="lg:col-span-1 flex flex-col space-y-6">
                  {/* Protocol Distribution */}
                  <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl flex flex-col justify-between flex-1">
                    <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2 uppercase">
                      Protocol Share
                    </h3>
                    <div className="h-40 flex items-center justify-center">
                      {(!results.protocols || results.protocols.length === 0) ? (
                        <div className="text-gray-500 italic text-xs font-mono">No protocol metrics</div>
                      ) : (
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={results.protocols}
                              cx="50%"
                              cy="50%"
                              innerRadius={30}
                              outerRadius={50}
                              paddingAngle={3}
                              dataKey="value"
                            >
                              {results.protocols.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]} />
                              ))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: 10, fontFamily: 'monospace' }} />
                            <Legend 
                              layout="vertical" 
                              verticalAlign="middle" 
                              align="right" 
                              wrapperStyle={{ fontSize: 9, fontFamily: 'monospace' }}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                      )}
                    </div>
                  </div>

                  {/* Attack Distribution by Signature */}
                  <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl flex flex-col justify-between flex-1">
                    <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2 uppercase">
                      Attack Distribution
                    </h3>
                    <div className="h-40 flex items-center justify-center">
                      {(!results.attacks || results.attacks.length === 0) ? (
                        <div className="text-gray-500 italic text-xs font-mono">No anomalies detected</div>
                      ) : (
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={results.attacks} layout="vertical" margin={{ top: 5, right: 10, left: 10, bottom: 5 }}>
                            <XAxis type="number" stroke="#4b5563" fontSize={8} />
                            <YAxis dataKey="name" type="category" stroke="#4b5563" fontSize={8} width={65} tickLine={false} />
                            <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: 9, fontFamily: 'monospace' }} />
                            <Bar dataKey="value" fill={COLOR_RED} radius={[0, 4, 4, 0]} name="Count" />
                          </BarChart>
                        </ResponsiveContainer>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Anomalies/Benign Traffic Explorer list */}
              <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-cyber-border pb-3 space-y-3 md:space-y-0">
                  <h3 className="text-sm font-bold font-mono text-white flex items-center space-x-2">
                    <Activity className="w-4 h-4 text-cyber-cyan animate-pulse" />
                    <span>TRAFFIC FLOW EXPLORER</span>
                  </h3>
                  
                  {/* Tabs Toggle */}
                  <div className="flex space-x-2 bg-cyber-dark/80 p-1 rounded-lg border border-cyber-border font-mono text-[10px]">
                    <button
                      onClick={() => handleShowTypeChange('anomalies')}
                      className={`px-3 py-1.5 rounded font-bold transition-all duration-200 cursor-pointer ${
                        showType === 'anomalies'
                          ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      CRITICAL ANOMALIES ({(results?.anomalies || []).length})
                    </button>
                    <button
                      onClick={() => handleShowTypeChange('benign')}
                      className={`px-3 py-1.5 rounded font-bold transition-all duration-200 cursor-pointer ${
                        showType === 'benign'
                          ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      BENIGN TRAFFIC ({(results?.benign || []).length})
                    </button>
                  </div>
                </div>

                {((showType === 'anomalies' ? results?.anomalies : results?.benign) || []).length === 0 ? (
                  <div className="bg-cyber-green/5 border border-cyber-green/20 text-cyber-green p-6 text-center font-mono text-sm rounded-lg flex items-center justify-center space-x-2">
                    <ShieldCheck className="w-5 h-5 text-cyber-green" />
                    <span>{showType === 'anomalies' ? 'No intrusions or malicious anomalies detected.' : 'No benign flows found in this traffic slice.'}</span>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {((showType === 'anomalies' ? results?.anomalies : results?.benign) || []).map((item, idx) => {
                      const isExpanded = expandedRow === idx;
                      const isItemAnomaly = item.prediction === 1;
                      return (
                        <div key={idx} className="border border-cyber-border rounded-xl bg-cyber-dark/40 overflow-hidden transition-all duration-300">
                          <div 
                            onClick={() => setExpandedRow(isExpanded ? null : idx)}
                            className="p-4 flex flex-col md:flex-row md:items-center md:justify-between cursor-pointer hover:bg-gray-800/20 font-mono text-xs select-none space-y-2 md:space-y-0"
                          >
                            <div className="flex flex-wrap items-center gap-3">
                              <span className={`w-6 h-6 rounded-full flex items-center justify-center font-bold text-[10px] border ${
                                isItemAnomaly 
                                  ? 'bg-cyber-red/10 text-cyber-red border-cyber-red/20' 
                                  : 'bg-cyber-green/10 text-cyber-green border-cyber-green/20'
                              }`}>
                                {idx + 1}
                              </span>
                              <span className="text-cyber-cyan font-semibold bg-cyber-dark/50 px-2 py-0.5 rounded border border-cyber-border/40 text-[10px]">
                                {fileMeta.extension.startsWith('.pcap') ? 'FLOW' : 'ROW'} #{item.file_row_number}
                              </span>
                              <span className="text-white font-semibold">SRC: {item.src_ip}</span>
                              <span className="text-gray-500">➔</span>
                              <span className="text-white font-semibold">DST: {item.dst_ip}:{item.dst_port}</span>
                            </div>

                            <div className="flex items-center justify-between md:justify-end space-x-4">
                              <span className={`px-2 py-0.5 rounded border font-bold uppercase text-[10px] ${
                                isItemAnomaly 
                                  ? 'bg-cyber-yellow/10 text-cyber-yellow border-cyber-yellow/20' 
                                  : 'bg-cyber-green/10 text-cyber-green border-cyber-green/20'
                              }`}>
                                {item.attack_type}
                              </span>
                              <span className={`font-bold font-mono ${isItemAnomaly ? 'text-cyber-red' : 'text-cyber-green'}`}>
                                CONF: {item.confidence}%
                              </span>
                              {isExpanded ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
                            </div>
                          </div>

                          {isExpanded && (
                            <div className="p-4 border-t border-cyber-border bg-cyber-card/60 grid grid-cols-1 lg:grid-cols-3 gap-6 animate-scanline-pane">
                              {/* Left column: Explanations */}
                              <div>
                                <ShapDetails 
                                  explanation={item.shap_explanation} 
                                  textExplanation={item.explanation_text} 
                                  attackType={item.attack_type} 
                                />
                              </div>
                              
                              {/* Middle column: Model Input Features */}
                              <div className="space-y-3 font-mono text-[10px]">
                                <h5 className="text-[11px] font-bold text-white uppercase border-b border-cyber-border pb-1">EXTRACTED FLOW DETAILS</h5>
                                <div className="grid grid-cols-1 gap-y-2 text-gray-300">
                                  {Object.entries(item.flow_details).map(([key, val]) => (
                                    <div key={key} className="flex justify-between py-0.5 border-b border-cyber-border/30">
                                      <span className="text-gray-500 uppercase">{key.replace(/_/g, ' ')}:</span>
                                      <span className="text-white font-semibold">{val}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>

                              {/* Right column: Original Raw Record */}
                              <div className="space-y-3 font-mono text-[10px]">
                                <h5 className="text-[11px] font-bold text-cyber-cyan uppercase border-b border-cyber-border pb-1 flex items-center space-x-1.5">
                                  <Tag className="w-3.5 h-3.5 text-cyber-cyan" />
                                  <span>ORIGINAL RAW RECORD</span>
                                </h5>
                                <div className="max-h-60 overflow-y-auto space-y-2 pr-1 scrollbar-thin">
                                  {item.raw_row && Object.entries(item.raw_row).map(([key, val]) => {
                                    // Check if key is a label column to highlight it
                                    const isLabelCol = ['label', 'true_label', 'class'].includes(key.toLowerCase());
                                    return (
                                      <div 
                                        key={key} 
                                        className={`flex justify-between py-1 px-1.5 border-b border-cyber-border/20 rounded ${
                                          isLabelCol ? 'bg-cyber-yellow/5 border-l-2 border-l-cyber-yellow' : ''
                                        }`}
                                      >
                                        <span className={`uppercase font-semibold ${isLabelCol ? 'text-cyber-yellow' : 'text-gray-400'}`}>
                                          {key}:
                                        </span>
                                        <span className={`font-semibold break-all text-right max-w-[65%] ${isLabelCol ? 'text-white font-bold' : 'text-gray-200'}`}>
                                          {val === null || val === undefined ? (
                                            <span className="text-gray-600 italic">null</span>
                                          ) : (
                                            String(val)
                                          )}
                                        </span>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Initial State / preview grid */}
          {!results && !analyzing && fileMeta && (
            <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl space-y-4">
              <h3 className="text-sm font-bold font-mono text-white">DATASET FILE PREVIEW (TOP 10 RECORDS)</h3>
              <div className="overflow-x-auto border border-cyber-border rounded-xl">
                <table className="w-full text-left font-mono text-[10px] whitespace-nowrap">
                  <thead className="bg-cyber-dark text-gray-400 border-b border-cyber-border">
                    <tr>
                      {fileMeta.preview.length > 0 && Object.keys(fileMeta.preview[0]).map((h) => (
                        <th key={h} className="p-3 border-r border-cyber-border text-center">{h.toUpperCase()}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border">
                    {fileMeta.preview.map((row, rIdx) => (
                      <tr key={rIdx} className="hover:bg-gray-800/10">
                        {Object.values(row).map((val, cIdx) => (
                          <td key={cIdx} className="p-3 border-r border-cyber-border text-center text-gray-300">
                            {typeof val === 'number' ? val.toFixed(4).replace(/\.?0+$/, '') : String(val)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
