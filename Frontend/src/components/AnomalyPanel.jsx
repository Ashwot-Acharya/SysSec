import { useState } from 'react';
import ParseTreeView from './ParseTreeView';

/**
 * AnomalyPanel — Displays anomaly alerts with score bars,
 * window sequences, and failure explanations.
 */
export default function AnomalyPanel({ anomalies }) {
  return (
    <div className="glass-card panel" id="anomaly-panel">
      <div className="panel-header">
        <div className="panel-title">
          <span className={`panel-title-dot ${anomalies.length > 0 ? 'red' : 'cyan'}`} />
          Anomaly Alerts
        </div>
        <span className="panel-badge">{anomalies.length} total</span>
      </div>

      <div className="anomaly-body">
        {anomalies.length === 0 ? (
          <div className="anomaly-empty">
            <div className="anomaly-empty-icon">🛡️</div>
            <div className="anomaly-empty-text">No anomalies detected</div>
            <div className="anomaly-empty-sub">System behavior appears normal</div>
          </div>
        ) : (
          [...anomalies].reverse().map((a, i) => (
            <AnomalyCard
              key={`${a.timestamp}-${i}`}
              anomaly={a}
              isNew={i === 0}
            />
          ))
        )}
      </div>
    </div>
  );
}

function AnomalyCard({ anomaly, isNew }) {
  const [showParseTree, setShowParseTree] = useState(false);

  const {
    timestamp,
    anomaly_score = 0,
    threshold = 0.7,
    window_sequence = [],
    failure_reason,
    failed_at_position,
    expected_tokens = [],
    parse_tree,
  } = anomaly;

  const scorePercent = Math.min(anomaly_score * 100, 100);

  return (
    <div className={`anomaly-card ${isNew ? 'new' : ''}`}>
      {/* Header */}
      <div className="anomaly-card-head">
        <div className="anomaly-tag">
          <span className="anomaly-tag-dot" />
          Anomaly
        </div>
        <span className="anomaly-ts">{timestamp}</span>
      </div>

      {/* Score Bar */}
      <div className="score-row">
        <span className="score-label">Score</span>
        <div className="score-bar-track">
          <div
            className="score-bar-fill"
            style={{ width: `${scorePercent}%` }}
          />
          <div
            className="score-bar-threshold"
            style={{ left: `${threshold * 100}%` }}
            title={`Threshold: ${threshold}`}
          />
        </div>
        <span className="score-value">{anomaly_score.toFixed(2)}</span>
      </div>

      {/* Failure Reason */}
      {failure_reason && (
        <div className="anomaly-reason">{failure_reason}</div>
      )}

      {/* Window Sequence */}
      {window_sequence.length > 0 && !showParseTree && (
        <div>
          <div className="anomaly-window-label">Syscall Window</div>
          <div className="anomaly-window">
            {window_sequence.map((token, idx) => (
              <span
                key={idx}
                className={`anomaly-token ${idx === failed_at_position ? 'failed' : ''}`}
              >
                {token}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Expected Tokens */}
      {expected_tokens.length > 0 && !showParseTree && (
        <div className="anomaly-expected">
          <div className="anomaly-expected-label">Expected Instead</div>
          <div className="anomaly-expected-tokens">
            {expected_tokens.map((token, idx) => (
              <span key={idx} className="expected-token">{token}</span>
            ))}
          </div>
        </div>
      )}

      {/* Parse Tree Toggle */}
      {parse_tree && (
        <>
          <button
            className="parse-tree-btn"
            onClick={() => setShowParseTree(!showParseTree)}
          >
            {showParseTree ? 'Hide Parse Tree ▲' : 'View Parse Tree ▼'}
          </button>
          
          {showParseTree && (
            <ParseTreeView anomaly={anomaly} onClose={() => setShowParseTree(false)} />
          )}
        </>
      )}
    </div>
  );
}
