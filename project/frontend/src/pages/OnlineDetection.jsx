import React, { useState, useEffect } from 'react';
import { Play, Square, Activity, ShieldAlert, Cpu, Terminal, RefreshCw, Layers, Shield, Eye, HelpCircle } from 'lucide-react';
import { startOnline, stopOnline, getOnlineStatus, getLogs, getInterfaces } from '../services/api';
import ConsoleLogs from '../components/ConsoleLogs';
import ShapDetails from '../components/ShapDetails';

export default function OnlineDetection({ addToast, systemStatus, setSystemStatus, dashboardStats, latestAlerts, fetchDashboard }) {
  const [option, setOption] = useState(1);
  
  // Inputs
  const [interfaceVal, setInterfaceVal] = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [portFilter, setPortFilter] = useState('');
  const [interfaceName, setInterfaceName] = useState('');
  const [pcapFile, setPcapFile] = useState(null);
  
  // States
  const [logs, setLogs] = useState([]);
  const [loadingAction, setLoadingAction] = useState(false);
  const [countdown, setCountdown] = useState(systemStatus.sliding_window_sec || 30);
  
  // Inject mock packet details
  const [injecting, setInjecting] = useState(false);
  
  // SHAP Explanation modal state
  const [selectedAlert, setSelectedAlert] = useState(null);
  
  // Available network interfaces
  const [interfaces, setInterfaces] = useState([]);

  useEffect(() => {
    fetchLogs();
    fetchInterfacesList();
    
    // Set default interface from status on load
    if (systemStatus.interface) {
      setInterfaceVal(systemStatus.interface);
    }
  }, [systemStatus]);

  async function fetchInterfacesList() {
    try {
      const data = await getInterfaces();
      setInterfaces(data);
    } catch (err) {
      console.error(err);
    }
  }

  // Countdown timer for custom sliding window
  useEffect(() => {
    let timer;
    if (systemStatus.is_running) {
      timer = setInterval(() => {
        setCountdown((prev) => {
          if (prev <= 1) {
            // Trigger dashboard stats update at the boundary
            fetchDashboard();
            return systemStatus.sliding_window_sec || 30; // reset
          }
          return prev - 1;
        });
      }, 1000);
    } else {
      setCountdown(systemStatus.sliding_window_sec || 30);
    }
    return () => clearInterval(timer);
  }, [systemStatus.is_running, systemStatus.sliding_window_sec]);

  async function fetchLogs() {
    try {
      const data = await getLogs(30);
      setLogs(data);
    } catch (err) {
      console.error(err);
    }
  }

  async function handleStart() {
    try {
      setLoadingAction(true);
      
      const payload = {
        option,
        interfaceVal,
        ipFilter,
        portFilter,
        interfaceName,
        pcapFile: option === 4 ? pcapFile : null
      };
      
      const data = await startOnline(payload);
      
      // Update status immediately
      const status = await getOnlineStatus();
      setSystemStatus(status);
      setCountdown(status.sliding_window_sec || 30);
      
      addToast(
        data.simulated 
          ? 'Online capture started in Simulation mode.' 
          : 'Online packet capture sniffing active.', 
        'success'
      );
      
      fetchLogs();
    } catch (err) {
      addToast(err.message || 'Failed to start online capture.', 'error');
    } finally {
      setLoadingAction(false);
    }
  }

  async function handleStop() {
    try {
      setLoadingAction(true);
      await stopOnline();
      
      const status = await getOnlineStatus();
      setSystemStatus(status);
      
      addToast('Online packet capture sniffer stopped.', 'info');
      fetchLogs();
    } catch (err) {
      addToast(err.message || 'Failed to stop capture.', 'error');
    } finally {
      setLoadingAction(false);
    }
  }

  // Inject a mock packet to test Endpoint option 5
  async function handleInjectPacket() {
    try {
      setInjecting(true);
      const randomIp = () => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`;
      const payload = {
        src_ip: randomIp(),
        dst_ip: "192.168.1.10",
        src_port: Math.floor(Math.random() * 64512) + 1024,
        dst_port: random.choice([80, 443, 22, 21]),
        protocol: "TCP",
        length: Math.floor(Math.random() * 1400) + 64,
        syn_flag: Math.random() > 0.85 ? 1 : 0,
        rst_flag: Math.random() > 0.95 ? 1 : 0,
        fin_flag: Math.random() > 0.95 ? 1 : 0
      };
      
      const res = await fetch('/api/online/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      
      if (!res.ok) throw new Error();
      
      addToast('Mock packet injected via API streaming channel.', 'success');
      fetchLogs();
    } catch (err) {
      addToast('Failed to inject mock packet.', 'error');
    } finally {
      setInjecting(false);
    }
  }

  const random = {
    choice: (arr) => arr[Math.floor(Math.random() * arr.length)]
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex items-center space-x-2 text-white font-mono border-b border-cyber-border pb-3 mb-6">
        <Activity className="w-5 h-5 text-cyber-cyan" />
        <h2 className="text-xl font-bold tracking-wider">ONLINE SNIFFER INTRUSION DETECTOR</h2>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sniffer Bind Configuration */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-xl relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-cyber-cyan/35" />
            <h3 className="text-sm font-bold font-mono text-white mb-4">CAPTURE PORT BINDING</h3>
            
            <div className="space-y-5 font-mono text-xs">
              {/* Option Selector */}
              <div className="space-y-2">
                <label className="block font-semibold text-gray-300">SNIFF METHOD</label>
                <select
                  value={option}
                  onChange={(e) => setOption(parseInt(e.target.value))}
                  disabled={systemStatus.is_running}
                  className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan transition-all"
                >
                  <option value={1}>Option 1: Default Interface Sniff</option>
                  <option value={2}>Option 2: BPF Filter Sniff (IP / Port)</option>
                  <option value={3}>Option 3: Name Interface sniffer</option>
                  <option value={4}>Option 4: PCAP Live Stream File Replay</option>
                  <option value={5}>Option 5: API Endpoint Injector</option>
                </select>
              </div>

              {/* Conditional Inputs */}
              {option === 1 && (
                <div className="space-y-2">
                  <label className="block font-semibold text-gray-300">INTERFACE SELECTOR</label>
                  <select
                    value={interfaceVal}
                    onChange={(e) => setInterfaceVal(e.target.value)}
                    disabled={systemStatus.is_running}
                    className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan"
                  >
                    <option value="">Default Network Interface</option>
                    {interfaces.length > 0 ? (
                      interfaces.map((iface) => (
                        <option key={iface.key} value={iface.key}>
                          {iface.description ? `${iface.description} (${iface.name})` : iface.name} {iface.ip ? ` [IP: ${iface.ip}]` : ''}
                        </option>
                      ))
                    ) : (
                      <>
                        <option value="Ethernet">Ethernet Adapter (Fallback)</option>
                        <option value="WiFi">Wireless LAN (WiFi) (Fallback)</option>
                      </>
                    )}
                  </select>
                </div>
              )}

              {option === 2 && (
                <div className="space-y-3">
                  <div className="space-y-1">
                    <label className="block font-semibold text-gray-300">IP ADDRESS FILTER</label>
                    <input
                      type="text"
                      placeholder="e.g. 192.168.1.1"
                      value={ipFilter}
                      onChange={(e) => setIpFilter(e.target.value)}
                      disabled={systemStatus.is_running}
                      className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block font-semibold text-gray-300">PORT NUMBER FILTER</label>
                    <input
                      type="number"
                      placeholder="e.g. 80, 443"
                      value={portFilter}
                      onChange={(e) => setPortFilter(e.target.value)}
                      disabled={systemStatus.is_running}
                      className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan"
                    />
                  </div>
                </div>
              )}

              {option === 3 && (
                <div className="space-y-2">
                  <label className="block font-semibold text-gray-300">INTERFACE NAME</label>
                  <input
                    type="text"
                    placeholder="e.g. wlan0, eth0"
                    value={interfaceName}
                    onChange={(e) => setInterfaceName(e.target.value)}
                    disabled={systemStatus.is_running}
                    className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan"
                  />
                </div>
              )}

              {option === 4 && (
                <div className="space-y-2">
                  <label className="block font-semibold text-gray-300">PCAP STREAM FILE</label>
                  <input
                    type="file"
                    accept=".pcap"
                    onChange={(e) => setPcapFile(e.target.files[0])}
                    disabled={systemStatus.is_running}
                    className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyber-cyan"
                  />
                </div>
              )}

              {option === 5 && (
                <div className="bg-cyber-dark/60 border border-cyber-border p-3.5 rounded-xl space-y-2 leading-relaxed">
                  <div className="font-bold text-cyber-cyan">API INJECT LINK:</div>
                  <code className="text-[10px] break-all block text-white bg-gray-950 p-1.5 rounded border border-gray-800">
                    POST /api/online/inject
                  </code>
                  <p className="text-[10px] text-gray-400">
                    Submit raw JSON flow packets directly to this network port.
                  </p>
                  
                  {systemStatus.is_running && (
                    <button
                      onClick={handleInjectPacket}
                      disabled={injecting}
                      className="mt-2 w-full py-1.5 bg-cyber-cyan/15 hover:bg-cyber-cyan/30 text-cyber-cyan font-bold border border-cyber-cyan/40 hover:border-cyber-cyan rounded transition-all cursor-pointer"
                    >
                      {injecting ? 'INJECTING PACKET...' : 'TEST PACKET INJECTOR'}
                    </button>
                  )}
                </div>
              )}

              {/* Start Stop Actions */}
              <div className="pt-2">
                {systemStatus.is_running ? (
                  <button
                    onClick={handleStop}
                    disabled={loadingAction}
                    className="w-full flex items-center justify-center space-x-2 py-3 bg-cyber-red hover:bg-cyber-red/85 text-white font-bold rounded-lg border border-cyber-red shadow-glow-red active:scale-95 transition-all duration-300 cursor-pointer disabled:opacity-50"
                  >
                    <Square className="w-4 h-4 fill-current" />
                    <span>STOP CAPTURE MONITOR</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStart}
                    disabled={loadingAction || (option === 4 && !pcapFile)}
                    className="w-full flex items-center justify-center space-x-2 py-3 bg-cyber-green hover:bg-cyber-green/85 text-cyber-dark font-bold rounded-lg border border-cyber-green shadow-glow-green active:scale-95 transition-all duration-300 cursor-pointer disabled:opacity-50"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    <span>START CAPTURE MONITOR</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Running Monitor Status */}
          {systemStatus.is_running && (
            <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4 shadow-xl font-mono text-xs relative overflow-hidden animate-scanline-pane">
              <h4 className="text-xs font-bold text-white uppercase border-b border-cyber-border pb-2 flex items-center space-x-1.5">
                <Layers className="text-cyber-cyan w-4 h-4 animate-spin" />
                <span>SLIDING WINDOW PROCESSOR</span>
              </h4>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">CONTEXT TIMER:</span>
                  <span className="text-cyber-cyan font-bold text-sm animate-pulse">{countdown} SEC REMAINING</span>
                </div>
                <div className="w-full bg-gray-800 h-2 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-cyber-cyan transition-all duration-1000 ease-linear shadow-glow-cyan"
                    style={{ width: `${(countdown / systemStatus.sliding_window_sec) * 100}%` }}
                  />
                </div>
                
                <div className="border-t border-cyber-border/40 pt-2.5 space-y-2 mt-2">
                  <div className="flex justify-between"><span className="text-gray-500">BUFFER PACKETS:</span><span className="text-white font-bold text-sm">{dashboardStats.total_packets || systemStatus.packet_count}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">ACTIVE FLOWS:</span><span className="text-white font-bold text-sm">{dashboardStats.total_flows || 0}</span></div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">CAPTURE ADAPTER:</span>
                    <span className="text-white uppercase text-[10px]">
                      {systemStatus.simulated ? 'SIMULATOR_THREAD' : (systemStatus.interface || systemStatus.interface_name || 'DEFAULT')}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Live Sniffer Alert logs & system diagnostic terminal */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active alerts log */}
          <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl space-y-4">
            <div className="flex justify-between items-center border-b border-cyber-border pb-3">
              <h3 className="text-sm font-bold font-mono text-white flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-cyber-red animate-pulse" />
                <span>LIVE INTRUSION EVENTS (THIS SLIDING WINDOW)</span>
              </h3>
              {systemStatus.is_running && (
                <div className="text-[10px] bg-cyber-red/10 border border-cyber-red/30 px-2 py-0.5 rounded text-cyber-red font-mono font-bold uppercase animate-pulse">
                  SNIFFING LIVE
                </div>
              )}
            </div>

            <div className="max-h-60 overflow-y-auto space-y-3 pr-2">
              {!systemStatus.is_running ? (
                <div className="text-gray-500 italic text-center py-10 font-mono text-xs">
                  Intrusion sniffer is idle. Activate capture port binding to stream alerts.
                </div>
              ) : latestAlerts.length === 0 ? (
                <div className="text-cyber-green border border-cyber-green/20 bg-cyber-green/5 text-center p-8 font-mono text-xs rounded-xl flex items-center justify-center space-x-2">
                  <Shield className="w-4 h-4 text-cyber-green" />
                  <span>No security intrusions identified in this sliding window. Target is safe.</span>
                </div>
              ) : (
                latestAlerts.map((alert) => {
                  const isThreat = alert.prediction === 1;
                  return (
                  <div key={alert.id} className={`border rounded-xl overflow-hidden ${isThreat ? "border-cyber-red/50 bg-cyber-red/5" : "border-cyber-border bg-cyber-dark/40"}`}>
                    <div className="p-3.5 flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center space-x-2">
                        <span className="text-gray-500">[{alert.timestamp.split(' ')[1]}]</span>
                        <span className={`font-bold uppercase ${isThreat ? "text-cyber-red" : "text-cyber-green"}`}>[{alert.attack_type}]</span>
                        <span className="text-gray-300 font-semibold">{alert.src_ip} ➔ {alert.dst_ip}:{alert.dst_port}</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className={`font-bold ${isThreat ? "text-cyber-red" : "text-cyber-green"}`}>CONFID: {alert.confidence}%</span>
                        <button
                          onClick={() => setSelectedAlert(alert)}
                          className="p-1 bg-cyber-cyan/15 hover:bg-cyber-cyan text-cyber-cyan hover:text-cyber-dark border border-cyber-cyan/35 hover:border-cyber-cyan rounded transition duration-200 cursor-pointer"
                          title="Inspect Anomaly"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                  );
                })
              )}
            </div>
          </div>

          {/* System diagnostics logs console component */}
          <ConsoleLogs logs={logs} onRefresh={fetchLogs} />
        </div>
      </div>

      {/* SHAP Explanation Modal Sidebar */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-2xl bg-cyber-card border-l border-cyber-border h-full shadow-2xl flex flex-col p-6 relative overflow-y-auto animate-scanline-pane">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4 mb-6">
              <div className="flex items-center space-x-2">
                <Cpu className="w-5 h-5 text-cyber-yellow" />
                <h3 className="text-lg font-bold font-mono text-white">
                  INCIDENT INVESTIGATION
                </h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-3 py-1.5 bg-gray-800 hover:bg-cyber-red/20 hover:text-cyber-red border border-gray-750 hover:border-cyber-red/30 rounded-lg text-xs font-mono text-gray-400 transition-all duration-300 cursor-pointer"
              >
                CLOSE
              </button>
            </div>

            <div className="space-y-6">
              {/* Traffic details overview */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-cyber-dark/40 border border-cyber-border p-4 rounded-xl text-center font-mono text-xs">
                <div>
                  <div className="text-[10px] text-gray-500">SOURCE IP</div>
                  <div className="text-sm font-bold text-white break-all">{selectedAlert.src_ip}</div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500">DESTINATION IP</div>
                  <div className="text-sm font-bold text-white break-all">{selectedAlert.dst_ip}:{selectedAlert.dst_port}</div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500">CONFIDENCE</div>
                  <div className="text-sm font-bold text-cyber-red">{selectedAlert.confidence}%</div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500">ISOLATION FOREST SCORE</div>
                  <div className="text-sm font-bold text-cyber-yellow">{selectedAlert.if_score}</div>
                </div>
              </div>

              {/* Local SHAP details component */}
              <ShapDetails 
                explanation={selectedAlert.shap_explanation} 
                textExplanation={selectedAlert.explanation_text}
                attackType={selectedAlert.attack_type}
              />
              
              {/* Flow Features details list */}
              <div className="space-y-3 font-mono text-[10px]">
                <h5 className="text-[11px] font-bold text-white uppercase border-b border-cyber-border pb-1">EXTRACTED FLOW FEATURES</h5>
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-gray-300">
                  {Object.entries(selectedAlert.flow_details).map(([key, val]) => (
                    <div key={key} className="flex justify-between py-0.5 border-b border-cyber-border/30">
                      <span className="text-gray-500 uppercase">{key.replace(/_/g, ' ')}:</span>
                      <span className="text-white font-semibold">{val}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
