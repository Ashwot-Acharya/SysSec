export default function ConnectionStatus({ status }) {
  const labels = {
    connected: 'Connected',
    connecting: 'Reconnecting…',
    disconnected: 'Disconnected',
  };

  return (
    <div className="connection-status" id="connection-status">
      <span className={`connection-dot ${status}`} />
      <span className={`connection-text ${status}`}>
        {labels[status] || 'Unknown'}
      </span>
    </div>
  );
}
