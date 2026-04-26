/**
 * ParseTreeView — Interactive parse tree visualization
 * Shows token-level parseability, span arcs, and breakdown details.
 */
export default function ParseTreeView({ anomaly, onClose }) {
  const parseTree = anomaly?.parse_tree;
  if (!parseTree) return null;

  const {
    token_parseable = [],
    breakdown,
    verdict,
    parse_spans = [],
  } = parseTree;

  const sequence = anomaly.window_sequence || [];
  const failedPos = anomaly.failed_at_position;

  if (sequence.length === 0) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close-btn" onClick={onClose}>✕</button>
        <div className="modal-title">
          <span>⚡</span> Parse Tree Visualization
        </div>

        <div className="parse-tree" id="parse-tree-view">
          {/* Verdict Banner */}
          {verdict && (
            <div className="parse-verdict">
              <span className="parse-verdict-icon">⚠</span>
              <span className="parse-verdict-text">{verdict}</span>
            </div>
          )}

          {/* Token Sequence with arcs */}
          <div className="parse-sequence-wrapper vertical">
            {/* Token Row */}
            <div className="parse-tokens vertical">
              {sequence.map((token, idx) => {
                const isParseable = token_parseable[idx] !== false;
                const isFailed = idx === failedPos;

                return (
                  <div
                    key={idx}
                    className={`parse-token ${isFailed ? 'failed' : isParseable ? 'valid' : 'invalid'}`}
                  >
                    <span className="parse-token-idx">{idx}</span>
                    <span className="parse-token-name">{token}</span>
                    <span className="parse-token-status">
                      {isFailed ? '✗' : isParseable ? '✓' : '?'}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Arc Layer (SVG) */}
            {parse_spans.length > 0 && (
              <svg className="parse-arcs vertical" viewBox={`0 0 60 ${sequence.length * 48}`} preserveAspectRatio="xMinYMin meet">
                {parse_spans.map((span, i) => {
                  const y1 = span.start * 48 + 24;
                  const y2 = span.end * 48 + 24;
                  const midY = (y1 + y2) / 2;
                  const arcWidth = 25;
                  const color = span.valid
                    ? 'rgba(0, 255, 136, 0.35)'
                    : 'rgba(255, 59, 92, 0.35)';

                  return (
                    <g key={i}>
                      <path
                        d={`M 5 ${y1} Q ${5 + arcWidth} ${midY} 5 ${y2}`}
                        fill="none"
                        stroke={color}
                        strokeWidth="1.5"
                        strokeLinecap="round"
                      />
                      <text
                        x={5 + arcWidth + 5}
                        y={midY}
                        textAnchor="middle"
                        transform={`rotate(90, ${5 + arcWidth + 5}, ${midY})`}
                        fill={span.valid ? 'rgba(0, 255, 136, 0.6)' : 'rgba(255, 59, 92, 0.6)'}
                        fontSize="7"
                        fontFamily="var(--font-mono)"
                      >
                        {span.label}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}
          </div>

          {/* Breakdown Detail */}
          {breakdown && (
            <div className="parse-breakdown">
              <div className="parse-breakdown-header">
                <span className="parse-breakdown-icon">🔍</span>
                Breakdown Analysis
              </div>
              <div className="parse-breakdown-grid">
                <div className="parse-breakdown-item">
                  <span className="parse-breakdown-label">Position</span>
                  <span className="parse-breakdown-value mono">{breakdown.position}</span>
                </div>
                <div className="parse-breakdown-item">
                  <span className="parse-breakdown-label">Syscall</span>
                  <span className="parse-breakdown-value mono failed-text">{breakdown.syscall}</span>
                </div>
                <div className="parse-breakdown-item">
                  <span className="parse-breakdown-label">Rule Violated</span>
                  <span className="parse-breakdown-value mono">{breakdown.rule_violated || "N/A"}</span>
                </div>
                <div className="parse-breakdown-item full-width">
                  <span className="parse-breakdown-label">Reason</span>
                  <span className="parse-breakdown-value">{breakdown.reason}</span>
                </div>
                {breakdown.context_before?.length > 0 && (
                  <div className="parse-breakdown-item">
                    <span className="parse-breakdown-label">Before</span>
                    <span className="parse-breakdown-value mono">
                      {breakdown.context_before.join(' → ')}
                    </span>
                  </div>
                )}
                {breakdown.context_after?.length > 0 && (
                  <div className="parse-breakdown-item">
                    <span className="parse-breakdown-label">After</span>
                    <span className="parse-breakdown-value mono">
                      {breakdown.context_after.join(' → ')}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
