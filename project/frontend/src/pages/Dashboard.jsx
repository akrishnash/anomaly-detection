import React from 'react';
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, 
  BarChart, Bar, PieChart, Pie, Cell, Legend, LineChart, Line
} from 'recharts';
import { ShieldCheck, ShieldAlert, Cpu, Activity, Award, Radio } from 'lucide-react';

export default function Dashboard({ stats, timeline, protocols, attacks, topSrcIps, topDstIps }) {
  
  // Custom colors for charts
  const COLOR_CYAN = '#06b6d4';
  const COLOR_GREEN = '#10b981';
  const COLOR_RED = '#ef4444';
  const COLOR_YELLOW = '#f59e0b';
  const COLOR_BLUE = '#3b82f6';
  
  const PROTOCOL_COLORS = [COLOR_CYAN, COLOR_BLUE, COLOR_YELLOW];

  const cardsData = [
    { label: 'TOTAL PACKETS', value: stats.total_packets, icon: Radio, color: 'text-cyber-cyan', border: 'border-cyber-cyan/35', shadow: 'shadow-glow-cyan' },
    { label: 'TOTAL FLOWS', value: stats.total_flows, icon: Activity, color: 'text-cyber-blue', border: 'border-cyber-blue/35', shadow: 'shadow-[0_0_15px_rgba(59,130,246,0.15)]' },
    { label: 'NORMAL FLOWS', value: stats.normal_flows, icon: ShieldCheck, color: 'text-cyber-green', border: 'border-cyber-green/35', shadow: 'shadow-glow-green' },
    { label: 'ATTACK FLOWS', value: stats.attack_flows, icon: ShieldAlert, color: 'text-cyber-red', border: 'border-cyber-red/35', shadow: 'shadow-glow-red' },
  ];

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div className="flex items-center justify-between pb-3 border-b border-cyber-border mb-6 font-mono">
        <div className="flex items-center space-x-2 text-white">
          <Cpu className="w-5 h-5 text-cyber-cyan" />
          <h2 className="text-xl font-bold tracking-wider">IDS REAL-TIME MONITORING CONSOLE</h2>
        </div>
        <div className="text-[10px] text-gray-500">REFRESHES EVERY 30 SECONDS</div>
      </div>

      {/* Stats Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {cardsData.map((c, i) => {
          const Icon = c.icon;
          return (
            <div 
              key={i} 
              className={`bg-cyber-card border ${c.border} rounded-2xl p-5 ${c.shadow} flex items-center justify-between transition-all duration-300 relative overflow-hidden`}
            >
              <div className="absolute top-0 left-0 bottom-0 w-1 bg-cyber-cyan/30" />
              <div className="space-y-1 font-mono">
                <span className="text-[10px] text-gray-500 font-bold block">{c.label}</span>
                <span className="text-2xl font-black text-white tracking-tight">{c.value || 0}</span>
              </div>
              <div className={`p-3 bg-gray-900/60 rounded-xl border border-cyber-border/30`}>
                <Icon className={`w-6 h-6 ${c.color}`} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Model confidence scores dashboard summary row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl relative overflow-hidden">
        {/* Decorative scanning line */}
        <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-cyber-cyan/20 animate-pulse-glow" />
        
        {/* Ensemble Anomaly Score Gauge */}
        <div className="flex items-center space-x-4 border-b md:border-b-0 md:border-r border-cyber-border/60 pb-4 md:pb-0 md:pr-4">
          <div className="p-3 bg-cyber-cyan/5 rounded-xl border border-cyber-cyan/20">
            <Award className="w-6 h-6 text-cyber-cyan" />
          </div>
          <div className="font-mono text-xs space-y-1">
            <span className="text-gray-500 font-bold uppercase block">ENSEMBLE ANOMALY SCORE</span>
            <div className="flex items-baseline space-x-2">
              <span className="text-lg font-bold text-white">{(stats.ensemble_score * 100).toFixed(2)}%</span>
              <span className="text-[10px] text-gray-400">avg threat probability</span>
            </div>
          </div>
        </div>

        {/* Isolation Forest Score */}
        <div className="flex items-center space-x-4 border-b md:border-b-0 md:border-r border-cyber-border/60 pb-4 md:pb-0 md:px-4">
          <div className="p-3 bg-cyber-yellow/5 rounded-xl border border-cyber-yellow/20">
            <Activity className="w-6 h-6 text-cyber-yellow" />
          </div>
          <div className="font-mono text-xs space-y-1">
            <span className="text-gray-500 font-bold uppercase block">ISOLATION FOREST SCORE</span>
            <div className="flex items-baseline space-x-2">
              <span className="text-lg font-bold text-white">{stats.if_score.toFixed(4)}</span>
              <span className="text-[10px] text-gray-400">avg anomaly score</span>
            </div>
          </div>
        </div>

        {/* Overall Detection rate */}
        <div className="flex items-center space-x-4 md:pl-4">
          <div className="p-3 bg-cyber-red/5 rounded-xl border border-cyber-red/20">
            <ShieldAlert className="w-6 h-6 text-cyber-red animate-pulse" />
          </div>
          <div className="font-mono text-xs space-y-1">
            <span className="text-gray-500 font-bold uppercase block">DETECTION RATE</span>
            <div className="flex items-baseline space-x-2">
              <span className="text-lg font-bold text-cyber-red">{stats.detection_rate}%</span>
              <span className="text-[10px] text-gray-400">threat ratio in active window</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Timeline Chart (Packets and Flow rate) */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl space-y-4">
          <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2">
            NETWORK INGESTION (PACKET & FLOW SPEED)
          </h3>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLOR_CYAN} stopOpacity={0.25}/>
                    <stop offset="95%" stopColor={COLOR_CYAN} stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorFlows" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLOR_BLUE} stopOpacity={0.25}/>
                    <stop offset="95%" stopColor={COLOR_BLUE} stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#4b5563" fontSize={9} tickLine={false} />
                <YAxis stroke="#4b5563" fontSize={9} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: 11, fontFamily: 'monospace' }}
                  labelClassName="text-cyber-cyan"
                />
                <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'monospace' }} />
                <Area type="monotone" dataKey="packets" stroke={COLOR_CYAN} strokeWidth={2} fillOpacity={1} fill="url(#colorPackets)" name="Packet Rate" />
                <Area type="monotone" dataKey="flows" stroke={COLOR_BLUE} strokeWidth={2} fillOpacity={1} fill="url(#colorFlows)" name="Flow Rate" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Prediction Timeline (Normal vs Attack Flows) */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl space-y-4">
          <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2">
            DETECTION CLASSIFICATIONS TIMELINE
          </h3>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
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
      </div>

      {/* Sub-distributions Section */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Protocol Distribution */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl flex flex-col justify-between">
          <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2">
            PROTOCOL SHARE
          </h3>
          <div className="h-44 flex items-center justify-center">
            {protocols.length === 0 ? (
              <div className="text-gray-500 italic text-xs font-mono">No protocol metrics</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocols}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {protocols.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: 10, fontFamily: 'monospace' }} />
                  <Legend 
                    layout="vertical" 
                    verticalAlign="middle" 
                    align="right" 
                    wrapperStyle={{ fontSize: 10, fontFamily: 'monospace' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Attack Category Breakdown */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl flex flex-col justify-between">
          <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2">
            ATTACK DISTRIBUTION BY SIGNATURE
          </h3>
          <div className="h-44 flex items-center justify-center">
            {attacks.length === 0 ? (
              <div className="text-gray-500 italic text-xs font-mono">No anomalies detected</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attacks} layout="vertical" margin={{ top: 5, right: 10, left: 10, bottom: 5 }}>
                  <XAxis type="number" stroke="#4b5563" fontSize={8} />
                  <YAxis dataKey="name" type="category" stroke="#4b5563" fontSize={8} width={80} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: 9, fontFamily: 'monospace' }} />
                  <Bar dataKey="value" fill={COLOR_RED} radius={[0, 4, 4, 0]} name="Count" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Source IPs / Nodes */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-xl flex flex-col justify-between">
          <h3 className="text-xs font-bold font-mono text-white tracking-wider border-b border-cyber-border pb-2">
            TOP INCIDENT HOSTS (SOURCE IP)
          </h3>
          <div className="h-44 flex flex-col justify-center space-y-2.5 font-mono text-xs">
            {topSrcIps.length === 0 ? (
              <div className="text-gray-500 italic text-center text-xs font-mono">No traffic hosts</div>
            ) : (
              topSrcIps.map((item, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between items-center text-[10px]">
                    <span className="text-white font-bold">{item.ip}</span>
                    <span className="text-cyber-cyan">{item.count} flows</span>
                  </div>
                  <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                    <div 
                      className="bg-cyber-cyan h-full shadow-glow-cyan" 
                      style={{ width: `${(item.count / topSrcIps[0].count) * 100}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
