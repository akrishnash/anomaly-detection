import React, { useState, useEffect } from 'react';
import { Save, Settings as SettingsIcon, AlertCircle, CheckCircle } from 'lucide-react';
import { getSettings, updateSettings } from '../services/api';

export default function Settings({ onSettingsChange }) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [config, setConfig] = useState({
    context_window: '30',
    model_selection: 'Hybrid Model',
    confidence_threshold: '0.5',
    packet_capture_interface: '',
    auto_refresh: 'true',
    dark_mode: 'true'
  });

  useEffect(() => {
    fetchConfig();
  }, []);

  async function fetchConfig() {
    try {
      setLoading(true);
      const data = await getSettings();
      setConfig(data);
    } catch (err) {
      setErrorMsg('Failed to load system configuration.');
    } finally {
      setLoading(false);
    }
  }

  async function handleSave(e) {
    e.preventDefault();
    try {
      setSaving(true);
      setSuccessMsg('');
      setErrorMsg('');
      await updateSettings(config);
      setSuccessMsg('Configuration saved and applied successfully.');
      if (onSettingsChange) {
        onSettingsChange();
      }
      setTimeout(() => setSuccessMsg(''), 4000);
    } catch (err) {
      setErrorMsg('Failed to update system configuration.');
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96 font-mono text-cyber-cyan animate-pulse">
        LOADING SYSTEM CONFIGURATIONS...
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="flex items-center space-x-2 text-white font-mono border-b border-cyber-border pb-3 mb-6">
        <SettingsIcon className="w-5 h-5 text-cyber-cyan" />
        <h2 className="text-xl font-bold tracking-wider">SYSTEM CONFIGURATION PANEL</h2>
      </div>

      {successMsg && (
        <div className="bg-cyber-green/10 border border-cyber-green/30 text-cyber-green px-4 py-3 rounded-lg flex items-center space-x-2 font-mono text-sm shadow-glow-green">
          <CheckCircle className="w-5 h-5" />
          <span>{successMsg}</span>
        </div>
      )}

      {errorMsg && (
        <div className="bg-cyber-red/10 border border-cyber-red/30 text-cyber-red px-4 py-3 rounded-lg flex items-center space-x-2 font-mono text-sm shadow-glow-red">
          <AlertCircle className="w-5 h-5" />
          <span>{errorMsg}</span>
        </div>
      )}

      <form onSubmit={handleSave} className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-6 shadow-xl relative overflow-hidden">
        {/* Decorative scanning line */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-cyber-cyan/50 shadow-glow-cyan animate-pulse-glow" />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Sliding Context Window */}
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-gray-300 font-mono">
              SLIDING CONTEXT WINDOW (SECONDS)
            </label>
            <input
              type="number"
              min="10"
              max="300"
              value={config.context_window}
              onChange={(e) => setConfig({ ...config, context_window: e.target.value })}
              className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-4 py-2.5 text-white font-mono focus:outline-none focus:border-cyber-cyan focus:shadow-glow-cyan transition-all duration-300"
              required
            />
            <p className="text-xs text-gray-500 font-mono">Time buffer (in seconds) to retain packets in memory before recalculating features.</p>
          </div>

          {/* Model Selection */}
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-gray-300 font-mono">
              MODEL SELECTION
            </label>
            <select
              value={config.model_selection}
              onChange={(e) => setConfig({ ...config, model_selection: e.target.value })}
              className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-4 py-2.5 text-white font-mono focus:outline-none focus:border-cyber-cyan focus:shadow-glow-cyan transition-all duration-300"
            >
              <option value="Isolation Forest">Isolation Forest (Unsupervised)</option>
              <option value="Hybrid Model">Unsupervised Ensemble (Isolation Forest + Autoencoder)</option>
            </select>
            <p className="text-xs text-gray-500 font-mono">Choose the core machine learning inference configuration.</p>
          </div>

          {/* Confidence Threshold */}
          <div className="space-y-2">
            <div className="flex justify-between items-center text-sm font-semibold text-gray-300 font-mono">
              <span>ATTACK THRESHOLD</span>
              <span className="text-cyber-cyan">{parseFloat(config.confidence_threshold).toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0.1"
              max="0.9"
              step="0.05"
              value={config.confidence_threshold}
              onChange={(e) => setConfig({ ...config, confidence_threshold: e.target.value })}
              className="w-full h-1.5 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-cyber-cyan"
            />
            <p className="text-xs text-gray-500 font-mono">Model confidence probability required to trigger threat alert diagnostics.</p>
          </div>

          {/* Bind Interface */}
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-gray-300 font-mono">
              DEFAULT NETWORK INTERFACE NAME
            </label>
            <input
              type="text"
              placeholder="e.g. WiFi, Ethernet"
              value={config.packet_capture_interface}
              onChange={(e) => setConfig({ ...config, packet_capture_interface: e.target.value })}
              className="w-full bg-cyber-dark border border-cyber-border rounded-lg px-4 py-2.5 text-white font-mono focus:outline-none focus:border-cyber-cyan focus:shadow-glow-cyan transition-all duration-300"
            />
            <p className="text-xs text-gray-500 font-mono">Default adapter interface name used for live sniffing when starting Online Mode.</p>
          </div>
        </div>

        <div className="border-t border-cyber-border pt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Auto Refresh Toggle */}
          <div className="flex items-center justify-between bg-cyber-dark/40 border border-cyber-border p-4 rounded-xl">
            <div className="font-mono">
              <div className="text-sm font-semibold text-white">AUTO REFRESH DASHBOARD</div>
              <div className="text-xs text-gray-500 mt-1">Poll server dynamically every context interval.</div>
            </div>
            <button
              type="button"
              onClick={() => setConfig({ ...config, auto_refresh: config.auto_refresh === 'true' ? 'false' : 'true' })}
              className={`w-12 h-6 flex items-center rounded-full p-1 transition-all duration-300 ${
                config.auto_refresh === 'true' ? 'bg-cyber-cyan' : 'bg-gray-800'
              }`}
            >
              <div
                className={`bg-white w-4.5 h-4.5 rounded-full shadow-md transform transition-all duration-300 ${
                  config.auto_refresh === 'true' ? 'translate-x-6' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Dark Mode Toggle */}
          <div className="flex items-center justify-between bg-cyber-dark/40 border border-cyber-border p-4 rounded-xl">
            <div className="font-mono">
              <div className="text-sm font-semibold text-white">CYBER NET GLOW THEME</div>
              <div className="text-xs text-gray-500 mt-1">Render modern glowing effects on cards and graphs.</div>
            </div>
            <button
              type="button"
              onClick={() => setConfig({ ...config, dark_mode: config.dark_mode === 'true' ? 'false' : 'true' })}
              className={`w-12 h-6 flex items-center rounded-full p-1 transition-all duration-300 ${
                config.dark_mode === 'true' ? 'bg-cyber-cyan' : 'bg-gray-800'
              }`}
            >
              <div
                className={`bg-white w-4.5 h-4.5 rounded-full shadow-md transform transition-all duration-300 ${
                  config.dark_mode === 'true' ? 'translate-x-6' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        </div>

        <div className="flex justify-end pt-4">
          <button
            type="submit"
            disabled={saving}
            className="flex items-center space-x-2 px-6 py-3 bg-cyber-cyan hover:bg-cyber-cyan/85 text-cyber-dark font-bold font-mono rounded-lg border border-cyber-cyan shadow-glow-cyan active:scale-95 transition-all duration-300 cursor-pointer disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'APPLYING CONFIG...' : 'SAVE & APPLY CONFIG'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
