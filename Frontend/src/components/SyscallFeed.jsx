import { useEffect, useRef } from 'react';

const MAX_ITEMS = 200;

/**
 * Classify a syscall name into a CSS color class.
 */
function syscallClass(name) {
  const n = name?.toLowerCase() || '';
  if (n === 'read') return 'sc-read';
  if (n === 'write') return 'sc-write';
  if (n === 'open' || n === 'openat') return 'sc-openat';
  if (n === 'close') return 'sc-close';
  if (n.startsWith('send')) return 'sc-sendto';
  if (n.startsWith('recv')) return 'sc-recvfrom';
  return 'sc-default';
}

/**
 * SyscallFeed — Live scrolling terminal feed of incoming syscalls.
 */
export default function SyscallFeed({ syscalls }) {
  const bodyRef = useRef(null);
  const isHovering = useRef(false);

  // Auto-scroll to bottom unless user is hovering (reading)
  useEffect(() => {
    if (!isHovering.current && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [syscalls]);

  // Trim to MAX_ITEMS for performance
  const visible = syscalls.slice(-MAX_ITEMS);

  return (
    <div className="glass-card panel" id="syscall-feed">
      <div className="panel-header">
        <div className="panel-title">
          <span className="panel-title-dot green" />
          Live Syscall Stream
        </div>
        <span className="panel-badge">{syscalls.length} captured</span>
      </div>

      <div
        className="feed-body"
        ref={bodyRef}
        onMouseEnter={() => { isHovering.current = true; }}
        onMouseLeave={() => { isHovering.current = false; }}
      >
        {visible.length === 0 ? (
          <div className="feed-empty">
            <div className="feed-empty-icon">⏳</div>
            <div>Waiting for syscall data…</div>
          </div>
        ) : (
          visible.map((sc, i) => (
            <div className="feed-row" key={`${sc.timestamp}-${i}`}>
              <span className="feed-ts">{sc.timestamp}</span>
              <span className="feed-pid">{sc.pid}</span>
              <span className="feed-thread">{sc.thread}</span>
              <span className={`feed-syscall ${syscallClass(sc.syscall)}`}>
                {sc.syscall}
              </span>
              <span className="feed-args">{sc.args}</span>
              <span className="feed-ret">
                {sc.return_value != null ? `→${sc.return_value}` : ''}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
