/**
 * AnomalyChart — SVG line chart of anomaly scores over time
 * with a threshold line and color-coded points.
 */
export default function AnomalyChart({ anomalies, threshold = 0.7 }) {
  const maxPoints = 50;
  const data = anomalies.slice(-maxPoints);

  const width = 900;
  const height = 160;
  const padX = 40;
  const padY = 20;
  const plotW = width - padX * 2;
  const plotH = height - padY * 2;

  // Y-axis: 0 to 1
  const yMin = 0;
  const yMax = 1;

  const toX = (i) => padX + (i / Math.max(data.length - 1, 1)) * plotW;
  const toY = (v) => padY + plotH - ((Math.min(v, yMax) - yMin) / (yMax - yMin)) * plotH;

  const thresholdY = toY(threshold);

  // Build SVG polyline points
  const linePoints = data.map((a, i) => `${toX(i)},${toY(a.anomaly_score)}`).join(' ');

  // Y-axis labels
  const yLabels = [0, 0.25, 0.5, 0.75, 1.0];

  return (
    <div className="glass-card chart-section" id="anomaly-chart">
      <div className="panel-header">
        <div className="panel-title">
          <span className="panel-title-dot cyan" />
          Anomaly Score Timeline
        </div>
        <span className="panel-badge">last {data.length} events</span>
      </div>

      <div className="chart-body">
        {data.length === 0 ? (
          <div className="chart-empty">No anomaly data yet — scores will appear here</div>
        ) : (
          <svg
            className="chart-svg"
            viewBox={`0 0 ${width} ${height}`}
            preserveAspectRatio="none"
          >
            {/* Grid lines */}
            {yLabels.map((v) => (
              <g key={v}>
                <line
                  x1={padX}
                  y1={toY(v)}
                  x2={width - padX}
                  y2={toY(v)}
                  stroke="rgba(255,255,255,0.05)"
                  strokeWidth="1"
                />
                <text
                  x={padX - 6}
                  y={toY(v) + 3}
                  textAnchor="end"
                  fill="rgba(255,255,255,0.2)"
                  fontSize="9"
                  fontFamily="var(--font-mono)"
                >
                  {v.toFixed(2)}
                </text>
              </g>
            ))}

            {/* Threshold line */}
            <line
              x1={padX}
              y1={thresholdY}
              x2={width - padX}
              y2={thresholdY}
              stroke="var(--cyan)"
              strokeWidth="1.5"
              strokeDasharray="6,4"
              opacity="0.6"
            />
            <text
              x={width - padX + 4}
              y={thresholdY + 3}
              fill="var(--cyan)"
              fontSize="8"
              fontFamily="var(--font-mono)"
              opacity="0.7"
            >
              THR
            </text>

            {/* Line */}
            {data.length > 1 && (
              <polyline
                points={linePoints}
                fill="none"
                stroke="var(--yellow)"
                strokeWidth="1.5"
                strokeLinejoin="round"
                strokeLinecap="round"
                opacity="0.7"
              />
            )}

            {/* Data points */}
            {data.map((a, i) => {
              const isAbove = a.anomaly_score >= threshold;
              return (
                <circle
                  key={i}
                  cx={toX(i)}
                  cy={toY(a.anomaly_score)}
                  r="3.5"
                  fill={isAbove ? 'var(--red)' : 'var(--green)'}
                  stroke={isAbove ? 'var(--red)' : 'var(--green)'}
                  strokeWidth="1"
                  opacity="0.9"
                >
                  <title>
                    Score: {a.anomaly_score.toFixed(3)} | {a.timestamp}
                  </title>
                </circle>
              );
            })}
          </svg>
        )}
      </div>
    </div>
  );
}
