import React, { useState, useEffect } from 'react';
import Dashboard from './pages/Dashboard';
import OnlineDetection from './pages/OnlineDetection';
import History from './pages/History';
import Settings from './pages/Settings';
import SentinelLayout from './sentinel/SentinelLayout';
import SocDashboard from './pages/sentinel/SocDashboard';
import DetectionPipeline from './pages/sentinel/DetectionPipeline';
import FlowExplorer from './pages/sentinel/FlowExplorer';
import DdosClassifier from './pages/sentinel/DdosClassifier';
import { getOnlineStatus, getDashboardData, getLatestPrediction, getLastRun, getModelHealth } from './services/api';
import { X, ShieldAlert, CheckCircle } from 'lucide-react';
import './sentinel/sentinel.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('soc');
  const [toasts, setToasts] = useState([]);

  // Last completed offline analysis (shared by all Sentinel screens)
  const [lastRun, setLastRun] = useState(null);
  const [lastRunTime, setLastRunTime] = useState(null);
  const [modelHealth, setModelHealth] = useState(null);
  const [explorerQuery, setExplorerQuery] = useState('');
  
  // Shared System State
  const [systemStatus, setSystemStatus] = useState({
    is_running: false,
    interface: '',
    packet_count: 0,
    sliding_window_sec: 30
  });

  const [dashboardStats, setDashboardStats] = useState({
    total_packets: 0,
    total_flows: 0,
    normal_flows: 0,
    suspicious_flows: 0,
    attack_flows: 0,
    detection_rate: 0.0,
    confidence_score: 0.0,
    if_score: 0.0,
    ensemble_score: 0.0
  });

  const [timeline, setTimeline] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [topSrcIps, setTopSrcIps] = useState([]);
  const [topDstIps, setTopDstIps] = useState([]);
  const [latestAlerts, setLatestAlerts] = useState([]);

  // Toast Handler
  function addToast(message, type = 'info') {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      removeToast(id);
    }, 4500);
  }

  function removeToast(id) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  // Fetch all live dashboard and status data
  async function fetchDashboard() {
    try {
      const statsData = await getDashboardData();
      setDashboardStats(statsData.stats);
      setTimeline(statsData.timeline);
      setProtocols(statsData.protocols);
      setAttacks(statsData.attacks);
      setTopSrcIps(statsData.top_src_ips);
      setTopDstIps(statsData.top_dst_ips);

      if (statsData.running) {
        const predData = await getLatestPrediction();
        setLatestAlerts(predData.alerts || []);
      }
    } catch (err) {
      console.error('Error fetching dashboard feeds:', err);
    }
  }

  async function fetchStatus() {
    try {
      const status = await getOnlineStatus();
      setSystemStatus(status);
    } catch (err) {
      console.error('Error fetching online system status:', err);
    }
  }

  // Initial load
  useEffect(() => {
    fetchStatus();
    fetchDashboard();
    getModelHealth().then(setModelHealth).catch(() => {});
    getLastRun()
      .then((data) => {
        if (data.available) {
          setLastRun(data.report);
          setLastRunTime(data.timestamp);
        }
      })
      .catch(() => {});
  }, []);

  function handleRunComplete(report) {
    setLastRun(report);
    setLastRunTime(new Date().toLocaleString());
    getModelHealth().then(setModelHealth).catch(() => {});
  }

  function jumpToExplorer(query) {
    setExplorerQuery(query || '');
    setActiveTab('explorer');
  }

  // Polling logic when sniffer is running
  useEffect(() => {
    let intervalId;
    if (systemStatus.is_running) {
      // Poll every 4 seconds to get snappy packet counter increments and graphs updates
      intervalId = setInterval(() => {
        fetchStatus();
        fetchDashboard();
      }, 4000);
    } else {
      // Poll static status less frequently when stopped
      intervalId = setInterval(() => {
        fetchStatus();
      }, 10000);
    }
    return () => clearInterval(intervalId);
  }, [systemStatus.is_running]);

  // Handle configuration changes
  function handleSettingsChange() {
    fetchStatus();
    fetchDashboard();
  }

  return (
    <SentinelLayout
      active={activeTab}
      onNavigate={setActiveTab}
      modelHealth={modelHealth}
      onSearch={jumpToExplorer}
    >
      <div className="transition-all duration-300">
        {activeTab === 'soc' && (
          <SocDashboard
            lastRun={lastRun}
            lastRunTime={lastRunTime}
            modelHealth={modelHealth}
            onNavigate={setActiveTab}
          />
        )}

        {activeTab === 'pipeline' && (
          <DetectionPipeline
            addToast={addToast}
            lastRun={lastRun}
            onRunComplete={handleRunComplete}
            onNavigate={setActiveTab}
            onInspectType={jumpToExplorer}
            modelHealth={modelHealth}
          />
        )}

        {activeTab === 'explorer' && (
          <FlowExplorer
            key={explorerQuery}
            lastRun={lastRun}
            initialQuery={explorerQuery}
            onNavigate={setActiveTab}
          />
        )}

        {activeTab === 'classifier' && (
          <DdosClassifier
            lastRun={lastRun}
            onNavigate={setActiveTab}
            onInspectType={jumpToExplorer}
          />
        )}

        {/* Legacy pages, rendered inside the Sentinel shell */}
        {activeTab === 'dashboard' && (
          <div className="max-w-7xl mx-auto">
            <Dashboard
              stats={dashboardStats}
              timeline={timeline}
              protocols={protocols}
              attacks={attacks}
              topSrcIps={topSrcIps}
              topDstIps={topDstIps}
            />
          </div>
        )}

        {activeTab === 'online' && (
          <div className="max-w-7xl mx-auto">
            <OnlineDetection
              addToast={addToast}
              systemStatus={systemStatus}
              setSystemStatus={setSystemStatus}
              dashboardStats={dashboardStats}
              latestAlerts={latestAlerts}
              fetchDashboard={fetchDashboard}
            />
          </div>
        )}

        {activeTab === 'history' && (
          <div className="max-w-7xl mx-auto">
            <History />
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="max-w-7xl mx-auto">
            <Settings onSettingsChange={handleSettingsChange} />
          </div>
        )}
      </div>

      {/* Toast Notification Container */}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col space-y-2.5 max-w-sm w-full font-mono text-xs">
        {toasts.map((t) => {
          const isError = t.type === 'error';
          const isSuccess = t.type === 'success';
          const iconColor = isError ? 'text-cyber-red' : (isSuccess ? 'text-cyber-green' : 'text-cyber-cyan');
          const borderColor = isError ? 'border-cyber-red/35 shadow-glow-red' : (isSuccess ? 'border-cyber-green/35 shadow-glow-green' : 'border-cyber-cyan/35 shadow-glow-cyan');
          const Icon = isError ? ShieldAlert : CheckCircle;
          
          return (
            <div
              key={t.id}
              className={`bg-cyber-card border ${borderColor} rounded-xl p-4 flex items-start space-x-3 text-white transition-all duration-300 relative overflow-hidden animate-scanline-pane`}
            >
              <div className="absolute top-0 left-0 bottom-0 w-1 bg-cyber-cyan/30" />
              <Icon className={`w-5 h-5 shrink-0 ${iconColor}`} />
              <div className="flex-1 select-text pr-4">{t.message}</div>
              <button 
                onClick={() => removeToast(t.id)}
                className="text-gray-500 hover:text-white transition duration-200"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </SentinelLayout>
  );
}
