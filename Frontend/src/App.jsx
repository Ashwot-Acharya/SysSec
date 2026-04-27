import { useState, useCallback } from 'react';
import './App.css';

import useWebSocket from './hooks/useWebSocket';
import ConnectionStatus from './components/ConnectionStatus';
import StatsBar from './components/StatsBar';
import SyscallFeed from './components/SyscallFeed';
import AnomalyPanel from './components/AnomalyPanel';
import AnomalyChart from './components/AnomalyChart';

const WS_URL = 'ws://localhost:8000/ws';
const MAX_SYSCALLS = 500;
const MAX_ANOMALIES = 100;

function App() {
  const [stats, setStats] = useState({});
  const [syscalls, setSyscalls] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [welcomeInfo, setWelcomeInfo] = useState(null);

  const handlers = {
    onSyscall: useCallback((msg) => {
      setSyscalls((prev) => {
        const next = [...prev, msg];
        return next.length > MAX_SYSCALLS ? next.slice(-MAX_SYSCALLS) : next;
      });
    }, []),

    onAnomaly: useCallback((msg) => {
      setAnomalies((prev) => {
        const next = [...prev, msg];
        return next.length > MAX_ANOMALIES ? next.slice(-MAX_ANOMALIES) : next;
      });
    }, []),

    onStats: useCallback((msg) => {
      setStats(msg);
    }, []),

    onWelcome: useCallback((msg) => {
      setWelcomeInfo(msg);
      setSyscalls([]);
      setAnomalies([]);
    }, []),
  };

  const { status } = useWebSocket(WS_URL, handlers);

  return (
    <div className="dashboard" id="dashboard">
      {/* ── Header ──────────────────────────────────────────────── */}
      <header className="header" id="header">
        <div className="header-left">
          <div className="header-logo">⚡</div>
          <div>
            <div className="header-title">
              Sys<span>Sec</span>
            </div>
            <div className="header-subtitle">
              Real-Time Syscall Anomaly Detection
            </div>
          </div>
        </div>
        <ConnectionStatus status={status} />
      </header>

      {/* ── Stats Bar ───────────────────────────────────────────── */}
      <StatsBar stats={stats} />

      {/* ── Main Grid: Feed + Anomalies ─────────────────────────── */}
      <div className="main-grid" id="main-content">
        <SyscallFeed syscalls={syscalls} />
        <AnomalyPanel anomalies={anomalies} />
      </div>

      {/* ── Chart ───────────────────────────────────────────────── */}
      <AnomalyChart
        anomalies={anomalies}
        threshold={welcomeInfo?.anomaly_threshold ?? 0.7}
      />
    </div>
  );
}

export default App;
