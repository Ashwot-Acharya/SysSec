import { useEffect, useRef, useState, useCallback } from 'react';

const RECONNECT_BASE_DELAY = 1000;
const RECONNECT_MAX_DELAY = 15000;

/**
 * Custom hook to manage WebSocket connection to the anomaly detection backend.
 *
 * @param {string} url - WebSocket URL (e.g. ws://localhost:8000/ws)
 * @param {object} handlers - Callback handlers keyed by message type
 *   { onSyscall, onAnomaly, onStats, onWelcome }
 */
export default function useWebSocket(url, handlers = {}) {
  const [status, setStatus] = useState('disconnected'); // 'connecting' | 'connected' | 'disconnected'
  const wsRef = useRef(null);
  const reconnectAttempt = useRef(0);
  const reconnectTimer = useRef(null);
  const handlersRef = useRef(handlers);

  // Keep handlers ref fresh without triggering reconnect
  useEffect(() => {
    handlersRef.current = handlers;
  }, [handlers]);

  const connect = useCallback(() => {
    // Cleanup any existing connection
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus('connecting');

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus('connected');
        reconnectAttempt.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          const h = handlersRef.current;

          switch (msg.type) {
            case 'syscall':
              h.onSyscall?.(msg);
              break;
            case 'anomaly':
              h.onAnomaly?.(msg);
              break;
            case 'stats':
              h.onStats?.(msg);
              break;
            case 'welcome':
              h.onWelcome?.(msg);
              break;
            case 'ping':
              // Respond with pong to keep connection alive
              ws.send(JSON.stringify({ type: 'pong' }));
              break;
            default:
              break;
          }
        } catch (err) {
          console.warn('[WS] Failed to parse message:', err);
        }
      };

      ws.onclose = (event) => {
        setStatus('disconnected');
        wsRef.current = null;

        // Auto-reconnect with exponential backoff
        if (!event.wasClean || event.code !== 1000) {
          const delay = Math.min(
            RECONNECT_BASE_DELAY * Math.pow(2, reconnectAttempt.current),
            RECONNECT_MAX_DELAY
          );
          reconnectAttempt.current += 1;
          reconnectTimer.current = setTimeout(() => {
            connect();
          }, delay);
        }
      };

      ws.onerror = () => {
        // onclose will fire after this, which handles reconnection
      };
    } catch (err) {
      console.error('[WS] Failed to create WebSocket:', err);
      setStatus('disconnected');
    }
  }, [url]);

  // Connect on mount, cleanup on unmount
  useEffect(() => {
    connect();

    return () => {
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close(1000, 'Component unmounted');
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { status };
}
