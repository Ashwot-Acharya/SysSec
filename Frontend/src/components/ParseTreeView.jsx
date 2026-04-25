/**
 * ParseTreeView — Interactive parse tree visualization
 * Shows token-level parseability, span arcs, and breakdown details.
 */
export default function ParseTreeView({ anomaly }) {
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
    <div className="parse-tree" id="parse-tree-view">
      {/* Verdict Banner */}
      {verdict && (
        <div className="parse-verdict">
          <span className="parse-verdict-icon">⚠</span>
          <span className="parse-verdict-text">{verdict}</span>
        </div>
      )}

      {/* Token Sequence with arcs */}
      <div className="parse-sequence-wrapper">
        {/* Arc Layer (SVG) */}
        {parse_spans.length > 0 && (
          <svg className="parse-arcs" viewBox={`0 0 ${sequence.length * 82} 40`} preserveAspectRatio="xMidYMax meet">
            {parse_spans.map((span, i) => {
              const x1 = span.start * 82 + 36;
              const x2 = span.end * 82 + 36;
              const midX = (x1 + x2) / 2;
              const arcHeight = 30;
              const color = span.valid
                ? 'rgba(0, 255, 136, 0.35)'
                : 'rgba(255, 59, 92, 0.35)';

              return (
                <g key={i}>
                  <path
                    d={`M ${x1} 38 Q ${midX} ${38 - arcHeight} ${x2} 38`}
                    fill="none"
                    stroke={color}
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                  <text
                    x={midX}
                    y={38 - arcHeight + 4}
                    textAnchor="middle"
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

        {/* Token Row */}
        <div className="parse-tokens">
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
              <span className="parse-breakdown-value mono">{breakdown.rule_violated}</span>
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
  );
}
