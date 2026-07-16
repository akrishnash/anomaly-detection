import React, { useState, useEffect } from 'react';
import { Search, Download, ShieldAlert, ShieldCheck, ChevronLeft, ChevronRight, Eye, Calendar, Tag } from 'lucide-react';
import { getHistory, getShapExplanation } from '../services/api';
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
  
  // SHAP Modal State
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapData, setShapData] = useState(null);

  useEffect(() => {
    fetchHistory();
  }, [page, search, mode, prediction, protocol, sortBy, sortOrder]);

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
      console.error(err);
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

  return (
    <div className="space-y-6">
      {/* Title & Exports Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-cyber-border gap-4">
        <div className="flex items-center space-x-2 text-white font-mono">
          <Calendar className="w-5 h-5 text-cyber-cyan" />
          <h2 className="text-xl font-bold tracking-wider">IDS DETECTION INCIDENT DATABASE</h2>
        </div>
        <div className="flex items-center space-x-3">
          <a
            href="/api/export-csv"
            download
            className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white font-mono text-sm border border-gray-700 rounded-lg hover:border-cyber-cyan/30 active:scale-95 transition-all duration-300"
          >
            <Download className="w-4 h-4" />
            <span>EXPORT CSV</span>
          </a>
          <a
            href="/api/download-pdf"
            download
            className="flex items-center space-x-2 px-4 py-2 bg-cyber-cyan/10 hover:bg-cyber-cyan/20 text-cyber-cyan font-mono text-sm border border-cyber-cyan/30 rounded-lg shadow-[0_0_8px_rgba(6,182,212,0.1)] active:scale-95 transition-all duration-300"
          >
            <Download className="w-4 h-4" />
            <span>DOWNLOAD PDF REPORT</span>
          </a>
        </div>
      </div>

      {/* Filters Section */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-4 bg-cyber-card border border-cyber-border p-4 rounded-xl shadow-lg">
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
            className="w-full bg-cyber-dark border border-cyber-border rounded-lg pl-9 pr-4 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-cyan transition-all"
          />
        </div>

        {/* Mode Filter */}
        <select
          value={mode}
          onChange={(e) => { setMode(e.target.value); setPage(1); }}
          className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-cyan"
        >
          <option value="">All Detection Modes</option>
          <option value="Offline">Offline</option>
          <option value="Online">Online</option>
        </select>

        {/* Classification Filter */}
        <select
          value={prediction}
          onChange={(e) => { setPrediction(e.target.value); setPage(1); }}
          className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-cyan"
        >
          <option value="">All Classifications</option>
          <option value="0">Benign (Normal)</option>
          <option value="1">Anomaly (Attack)</option>
        </select>

        {/* Protocol Filter */}
        <select
          value={protocol}
          onChange={(e) => { setProtocol(e.target.value); setPage(1); }}
          className="bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-cyan"
        >
          <option value="">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="Other">Other</option>
        </select>
        
        {/* Total Records Counter */}
        <div className="flex items-center justify-end font-mono text-xs text-gray-500 px-2">
          <span>RECORDS: {total}</span>
        </div>
      </div>

      {/* Main Grid */}
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
                  <td colSpan="11" className="p-12 text-center text-cyber-cyan animate-pulse">
                    FETCHING INCIDENT LOG DATA...
                  </td>
                </tr>
              ) : records.length === 0 ? (
                <tr>
                  <td colSpan="11" className="p-12 text-center text-gray-500 italic">
                    No matching threat records detected.
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
                        <span className={`px-2 py-0.5 rounded text-[10px] ${
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
                        {record.confidence.toFixed(2)}%
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
            PAGE {page} OF {totalPages}
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPage(Math.max(page - 1, 1))}
              disabled={page === 1}
              className="p-1.5 bg-gray-800 hover:bg-gray-700 text-white rounded-lg border border-gray-700 disabled:opacity-30 disabled:pointer-events-none active:scale-95 transition-all"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage(Math.min(page + 1, totalPages))}
              disabled={page === totalPages}
              className="p-1.5 bg-gray-800 hover:bg-gray-700 text-white rounded-lg border border-gray-700 disabled:opacity-30 disabled:pointer-events-none active:scale-95 transition-all"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* SHAP Explainability Sidebar / Modal Drawer */}
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
                      <div className="text-sm font-bold text-cyber-red">{selectedRecord.confidence.toFixed(2)}%</div>
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
