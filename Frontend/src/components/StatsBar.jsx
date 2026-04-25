/**
 * StatsBar — Displays 4 key metrics from the backend stats broadcast.
 */
export default function StatsBar({ stats }) {
  const {
    total_syscalls = 0,
    total_anomalies = 0,
    anomaly_rate = 0,
    recent_syscalls_per_second = 0,
  } = stats;

  return (
    <div className="stats-bar" id="stats-bar">
      {/* Total Syscalls */}
      <div className="glass-card stat-card cyan" id="stat-total-syscalls">
        <div className="stat-label">Total Syscalls</div>
        <div className="stat-value cyan">
          {total_syscalls.toLocaleString()}
        </div>
        <div className="stat-suffix">processed</div>
      </div>

      {/* Total Anomalies */}
      <div className="glass-card stat-card red" id="stat-total-anomalies">
        <div className="stat-label">Anomalies Detected</div>
        <div className="stat-value red">
          {total_anomalies.toLocaleString()}
        </div>
        <div className="stat-suffix">flagged</div>
      </div>

      {/* Anomaly Rate */}
      <div className="glass-card stat-card yellow" id="stat-anomaly-rate">
        <div className="stat-label">Anomaly Rate</div>
        <div className="stat-value yellow">
          {(anomaly_rate * 100).toFixed(3)}%
        </div>
        <div className="stat-suffix">of total</div>
      </div>

      {/* Syscalls Per Second */}
      <div className="glass-card stat-card green" id="stat-rps">
        <div className="stat-label">Throughput</div>
        <div className="stat-value green">
          {recent_syscalls_per_second}
        </div>
        <div className="stat-suffix">syscalls/sec</div>
      </div>
    </div>
  );
}
