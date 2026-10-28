import React, { useState, useEffect } from 'react';

export default function App() {
  const [account, setAccount] = useState(null);
  const [session, setSession] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [guardMode, setGuardMode] = useState('session-guard');
  const [logs, setLogs] = useState([]);
  const [stepUpChallenge, setStepUpChallenge] = useState(null);
  const [stepUpPassword, setStepUpPassword] = useState('');
  const [stepUpError, setStepUpError] = useState('');

  // Form states
  const [loginEmail, setLoginEmail] = useState('alice@example.com');
  const [loginPassword, setLoginPassword] = useState('SecurePass123!');
  const [isRegistering, setIsRegistering] = useState(false);
  const [regName, setRegName] = useState('Alice Doe');

  // Sensitive action state
  const [newPassword, setNewPassword] = useState('');
  const [recoveryEmail, setRecoveryEmail] = useState('');
  const [actionMessage, setActionMessage] = useState(null);

  // Mail Sink alerts
  const [notifications, setNotifications] = useState([]);

  const addLog = (method, path, status, decision, score, durationMs) => {
    setLogs(prev => [
      {
        id: Date.now() + Math.random(),
        time: new Date().toLocaleTimeString(),
        method,
        path,
        status,
        decision: decision || 'Allow',
        score: score || '0.00',
        durationMs
      },
      ...prev.slice(0, 19)
    ]);
  };

  const apiFetch = async (path, options = {}) => {
    const startTime = performance.now();
    const headers = {
      'Content-Type': 'application/json',
      'X-Session-Guard-Mode': guardMode,
      ...(options.headers || {})
    };

    try {
      const res = await fetch(path, { ...options, headers });
      const durationMs = Math.round(performance.now() - startTime);
      const decision = res.headers.get('X-Session-Guard-Decision') || (res.status === 403 ? 'Reject' : 'Allow');
      const score = res.headers.get('X-Session-Guard-Score') || '—';

      addLog(options.method || 'GET', path, res.status, decision, score, durationMs);

      // Handle Step-Up
      if (res.status === 428) {
        const body = await res.json();
        setStepUpChallenge(body.challengeToken);
        return { ok: false, status: 428, body };
      }

      // Handle Session Terminated
      if (res.status === 403 && (decision === 'Terminate+Notify' || decision === 'Reject')) {
        const body = await res.json();
        if (body.code === 'SESSION_TERMINATED' || body.code === 'NETWORK_BINDING_REJECT' || body.code === 'NETWORK_UA_REJECT') {
          setSession(null);
          setAccount(null);
          setActionMessage({ type: 'danger', text: `Access Rejected: ${body.reason || body.error}` });
          fetchNotifications();
          return { ok: false, status: 403, body };
        }
      }

      let body = {};
      try {
        body = await res.json();
      } catch {}

      return { ok: res.ok, status: res.status, body };
    } catch (err) {
      const durationMs = Math.round(performance.now() - startTime);
      addLog(options.method || 'GET', path, 'ERR', 'Error', '—', durationMs);
      return { ok: false, error: err.message };
    }
  };

  const checkSession = async () => {
    const res = await apiFetch('/api/auth/session');
    if (res.ok && res.body.account) {
      setAccount(res.body.account);
      setSession(res.body.session);
    } else {
      setAccount(null);
      setSession(null);
    }
  };

  const fetchNotifications = async () => {
    try {
      const res = await fetch('http://127.0.0.1:5025/api/mail/inbox');
      if (res.ok) {
        const data = await res.json();
        setNotifications(data.messages || []);
      }
    } catch {
      // mail sink might be on separate port
      const res = await fetch('/api/notifications/list');
      if (res.ok) {
        const data = await res.json();
        setNotifications(data.notifications || []);
      }
    }
  };

  useEffect(() => {
    checkSession();
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setActionMessage(null);
    const endpoint = isRegistering ? '/api/auth/register' : '/api/auth/login';
    const payload = isRegistering
      ? { email: loginEmail, password: loginPassword, name: regName }
      : { email: loginEmail, password: loginPassword };

    const res = await apiFetch(endpoint, {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      if (isRegistering) {
        setIsRegistering(false);
        setActionMessage({ type: 'success', text: 'Registration successful! Please log in.' });
      } else {
        setAccount(res.body.account);
        setSession({ id: res.body.sessionId });
        setActiveTab('dashboard');
        setActionMessage({ type: 'success', text: 'Logged in successfully with rotated session ID.' });
      }
    } else {
      setActionMessage({ type: 'danger', text: res.body?.error || 'Authentication failed.' });
    }
  };

  const handleLogout = async () => {
    await apiFetch('/api/auth/logout', { method: 'POST' });
    setAccount(null);
    setSession(null);
    setActiveTab('dashboard');
    setActionMessage({ type: 'info', text: 'Logged out successfully.' });
  };

  const handleSensitiveAction = async (path, body, title) => {
    setActionMessage(null);
    const res = await apiFetch(path, {
      method: 'POST',
      body: JSON.stringify(body)
    });

    if (res.ok) {
      setActionMessage({ type: 'success', text: `${title}: Succeeded! Response code 200.` });
    } else if (res.status === 428) {
      setActionMessage({ type: 'warning', text: 'Step-Up Required: Verification challenge triggered.' });
    } else {
      setActionMessage({ type: 'danger', text: `${title} Failed (${res.status}): ${res.body?.error || 'Rejected'}` });
    }
  };

  const submitStepUp = async (e) => {
    e.preventDefault();
    setStepUpError('');
    const res = await apiFetch('/api/auth/step-up', {
      method: 'POST',
      body: JSON.stringify({
        challengeToken: stepUpChallenge,
        password: stepUpPassword
      })
    });

    if (res.ok) {
      setStepUpChallenge(null);
      setStepUpPassword('');
      setActionMessage({ type: 'success', text: 'Step-Up verified successfully! Baseline re-established.' });
    } else {
      setStepUpError(res.body?.error || 'Verification failed.');
      if (res.status === 403) {
        setStepUpChallenge(null);
        setAccount(null);
        setSession(null);
      }
    }
  };

  const handleFeedback = async (token, action) => {
    const res = await fetch('/api/notifications/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, action })
    });
    if (res.ok) {
      fetchNotifications();
      setActionMessage({ type: 'info', text: `Feedback recorded: "${action === 'confirmed_me' ? 'This was me' : 'This was NOT me'}".` });
    }
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', padding: '24px 16px' }}>
      {/* Top Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 8, background: '#0284c7', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold' }}>
            SG
          </div>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: '#38bdf8' }}>SessionGuard</h1>
            <p style={{ fontSize: 13, color: '#94a3b8' }}>Session-Integrity & Hijack Detection System</p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-secondary)', padding: '6px 12px', borderRadius: 8, border: '1px solid var(--border-color)' }}>
            <span style={{ fontSize: 13, color: '#94a3b8' }}>Mode:</span>
            <select
              value={guardMode}
              onChange={e => setGuardMode(e.target.value)}
              style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontWeight: 600, outline: 'none' }}
            >
              <option value="session-guard" style={{ background: '#1e293b' }}>SessionGuard (Multi-Signal)</option>
              <option value="network-ua" style={{ background: '#1e293b' }}>Network + User-Agent</option>
              <option value="network-binding" style={{ background: '#1e293b' }}>Network Binding</option>
              <option value="token-only" style={{ background: '#1e293b' }}>Token Only</option>
            </select>
          </div>

          {account ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: 14, color: '#e2e8f0' }}>{account.email}</span>
              <button onClick={handleLogout} style={{ background: '#334155', color: '#f8fafc', border: 'none', padding: '6px 14px' }}>
                Logout
              </button>
            </div>
          ) : (
            <span style={{ fontSize: 13, color: '#ef4444' }}>Not Authenticated</span>
          )}
        </div>
      </header>

      {/* Action Banner */}
      {actionMessage && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 8,
          marginBottom: 20,
          background: actionMessage.type === 'danger' ? '#450a0a' : actionMessage.type === 'warning' ? '#451a03' : actionMessage.type === 'success' ? '#064e3b' : '#0c4a6e',
          color: actionMessage.type === 'danger' ? '#fca5a5' : actionMessage.type === 'warning' ? '#fcd34d' : actionMessage.type === 'success' ? '#6ee7b7' : '#7dd3fc',
          border: `1px solid ${actionMessage.type === 'danger' ? '#991b1b' : actionMessage.type === 'warning' ? '#d97706' : actionMessage.type === 'success' ? '#059669' : '#0284c7'}`
        }}>
          {actionMessage.text}
        </div>
      )}

      {/* Step-Up Challenge Modal */}
      {stepUpChallenge && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: '#1e293b', border: '1px solid #d97706', borderRadius: 12, padding: 28, width: 420, boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)' }}>
            <h3 style={{ color: '#f59e0b', marginBottom: 12 }}>⚠️ Step-Up Verification Required</h3>
            <p style={{ fontSize: 14, color: '#94a3b8', marginBottom: 16 }}>
              A moderate anomaly or risk deviation was detected. Please verify your password to re-establish your baseline and continue.
            </p>
            {stepUpError && <div style={{ color: '#ef4444', fontSize: 13, marginBottom: 12 }}>{stepUpError}</div>}
            <form onSubmit={submitStepUp}>
              <input
                type="password"
                placeholder="Enter account password"
                value={stepUpPassword}
                onChange={e => setStepUpPassword(e.target.value)}
                required
                style={{ width: '100%', padding: '10px 12px', background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#f8fafc', marginBottom: 16 }}
              />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button
                  type="button"
                  onClick={() => setStepUpChallenge(null)}
                  style={{ background: 'transparent', border: '1px solid #475569', color: '#94a3b8', padding: '8px 16px' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ background: '#f59e0b', border: 'none', color: '#000', fontWeight: 600, padding: '8px 18px' }}
                >
                  Confirm & Rebaseline
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24 }}>
        {/* Left Column: Tabs & Views */}
        <div>
          {/* Tab Navigation */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
            {['dashboard', 'sensitive', 'notifications'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  background: activeTab === tab ? '#0284c7' : 'var(--bg-secondary)',
                  color: activeTab === tab ? '#ffffff' : '#94a3b8',
                  border: '1px solid var(--border-color)',
                  padding: '8px 18px',
                  textTransform: 'capitalize'
                }}
              >
                {tab === 'sensitive' ? 'Sensitive Actions' : tab}
              </button>
            ))}
          </div>

          {/* TAB 1: Dashboard / Login */}
          {activeTab === 'dashboard' && (
            <div style={{ background: 'var(--bg-card)', padding: 24, borderRadius: 12, border: '1px solid var(--border-color)' }}>
              {account ? (
                <div>
                  <h2 style={{ fontSize: 18, marginBottom: 16 }}>Authenticated Session Dashboard</h2>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
                    <div style={{ background: '#0f172a', padding: 16, borderRadius: 8 }}>
                      <div style={{ fontSize: 12, color: '#94a3b8' }}>Account Email</div>
                      <div style={{ fontSize: 16, fontWeight: 600, color: '#38bdf8' }}>{account.email}</div>
                    </div>
                    <div style={{ background: '#0f172a', padding: 16, borderRadius: 8 }}>
                      <div style={{ fontSize: 12, color: '#94a3b8' }}>Active Session ID</div>
                      <div style={{ fontSize: 13, fontFamily: 'monospace', color: '#10b981' }}>{session?.id ? session.id.substring(0, 18) + '...' : 'None'}</div>
                    </div>
                  </div>

                  <h3 style={{ fontSize: 15, marginBottom: 12 }}>Protected Route Probing</h3>
                  <div style={{ display: 'flex', gap: 10 }}>
                    <button
                      onClick={() => apiFetch('/api/user/profile')}
                      style={{ background: '#334155', border: 'none', color: '#f8fafc', padding: '8px 14px' }}
                    >
                      GET /api/user/profile
                    </button>
                    <button
                      onClick={() => apiFetch('/api/user/dashboard')}
                      style={{ background: '#334155', border: 'none', color: '#f8fafc', padding: '8px 14px' }}
                    >
                      GET /api/user/dashboard
                    </button>
                    <button
                      onClick={() => apiFetch('/api/user/settings')}
                      style={{ background: '#334155', border: 'none', color: '#f8fafc', padding: '8px 14px' }}
                    >
                      GET /api/user/settings
                    </button>
                  </div>
                </div>
              ) : (
                <div>
                  <h2 style={{ fontSize: 18, marginBottom: 8 }}>{isRegistering ? 'Register Account' : 'Sign In'}</h2>
                  <p style={{ fontSize: 13, color: '#94a3b8', marginBottom: 20 }}>
                    {isRegistering ? 'Create a synthetic user for testing.' : 'Log in to generate an active session with baseline record.'}
                  </p>
                  <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    {isRegistering && (
                      <div>
                        <label style={{ fontSize: 13, color: '#94a3b8', display: 'block', marginBottom: 6 }}>Full Name</label>
                        <input
                          type="text"
                          value={regName}
                          onChange={e => setRegName(e.target.value)}
                          style={{ width: '100%', padding: '10px 12px', background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#f8fafc' }}
                        />
                      </div>
                    )}
                    <div>
                      <label style={{ fontSize: 13, color: '#94a3b8', display: 'block', marginBottom: 6 }}>Email</label>
                      <input
                        type="email"
                        value={loginEmail}
                        onChange={e => setLoginEmail(e.target.value)}
                        required
                        style={{ width: '100%', padding: '10px 12px', background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#f8fafc' }}
                      />
                    </div>
                    <div>
                      <label style={{ fontSize: 13, color: '#94a3b8', display: 'block', marginBottom: 6 }}>Password</label>
                      <input
                        type="password"
                        value={loginPassword}
                        onChange={e => setLoginPassword(e.target.value)}
                        required
                        style={{ width: '100%', padding: '10px 12px', background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#f8fafc' }}
                      />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
                      <button
                        type="button"
                        onClick={() => setIsRegistering(!isRegistering)}
                        style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontSize: 13 }}
                      >
                        {isRegistering ? 'Already have an account? Sign in' : 'Need an account? Register'}
                      </button>
                      <button
                        type="submit"
                        style={{ background: '#0284c7', border: 'none', color: '#fff', padding: '10px 24px', fontWeight: 600 }}
                      >
                        {isRegistering ? 'Register' : 'Sign In'}
                      </button>
                    </div>
                  </form>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: Sensitive Actions */}
          {activeTab === 'sensitive' && (
            <div style={{ background: 'var(--bg-card)', padding: 24, borderRadius: 12, border: '1px solid var(--border-color)' }}>
              <h2 style={{ fontSize: 18, marginBottom: 8 }}>High-Impact Sensitive Actions</h2>
              <p style={{ fontSize: 13, color: '#94a3b8', marginBottom: 20 }}>
                These routes carry weight <code style={{ color: '#38bdf8' }}>w_A = 0.20</code>. Triggering them without proper context, or concurrently, evaluates high risk.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Change Password */}
                <div style={{ background: '#0f172a', padding: 16, borderRadius: 8, border: '1px solid #334155' }}>
                  <h4 style={{ color: '#f8fafc', marginBottom: 8 }}>1. Change Password (/api/sensitive/change-password)</h4>
                  <div style={{ display: 'flex', gap: 10 }}>
                    <input
                      type="password"
                      placeholder="New password"
                      value={newPassword}
                      onChange={e => setNewPassword(e.target.value)}
                      style={{ flex: 1, padding: '8px 12px', background: '#1e293b', border: '1px solid #334155', borderRadius: 6, color: '#f8fafc' }}
                    />
                    <button
                      onClick={() => handleSensitiveAction('/api/sensitive/change-password', { newPassword: newPassword || 'NewSecurePass999!' }, 'Change Password')}
                      style={{ background: '#e11d48', border: 'none', color: '#fff', padding: '8px 16px' }}
                    >
                      Execute
                    </button>
                  </div>
                </div>

                {/* Disable MFA */}
                <div style={{ background: '#0f172a', padding: 16, borderRadius: 8, border: '1px solid #334155' }}>
                  <h4 style={{ color: '#f8fafc', marginBottom: 8 }}>2. Disable MFA (/api/sensitive/disable-mfa)</h4>
                  <button
                    onClick={() => handleSensitiveAction('/api/sensitive/disable-mfa', {}, 'Disable MFA')}
                    style={{ background: '#e11d48', border: 'none', color: '#fff', padding: '8px 16px' }}
                  >
                    Execute Disable MFA
                  </button>
                </div>

                {/* Update Recovery Email */}
                <div style={{ background: '#0f172a', padding: 16, borderRadius: 8, border: '1px solid #334155' }}>
                  <h4 style={{ color: '#f8fafc', marginBottom: 8 }}>3. Recovery Email (/api/sensitive/recovery-email)</h4>
                  <div style={{ display: 'flex', gap: 10 }}>
                    <input
                      type="email"
                      placeholder="recovery@example.com"
                      value={recoveryEmail}
                      onChange={e => setRecoveryEmail(e.target.value)}
                      style={{ flex: 1, padding: '8px 12px', background: '#1e293b', border: '1px solid #334155', borderRadius: 6, color: '#f8fafc' }}
                    />
                    <button
                      onClick={() => handleSensitiveAction('/api/sensitive/recovery-email', { recoveryEmail: recoveryEmail || 'newrecovery@example.com' }, 'Recovery Email')}
                      style={{ background: '#e11d48', border: 'none', color: '#fff', padding: '8px 16px' }}
                    >
                      Update Email
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Notifications & Feedback */}
          {activeTab === 'notifications' && (
            <div style={{ background: 'var(--bg-card)', padding: 24, borderRadius: 12, border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <div>
                  <h2 style={{ fontSize: 18 }}>Out-of-Band Security Alerts (Mock Mail Sink)</h2>
                  <p style={{ fontSize: 13, color: '#94a3b8' }}>
                    Real notifications delivered to the local mail sink with interactive feedback buttons.
                  </p>
                </div>
                <button
                  onClick={fetchNotifications}
                  style={{ background: '#334155', border: 'none', color: '#f8fafc', padding: '6px 12px', fontSize: 13 }}
                >
                  Refresh
                </button>
              </div>

              {notifications.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 32, color: '#64748b' }}>
                  No security alerts in inbox. Run an attack scenario to trigger containment and alerts.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  {notifications.map(msg => (
                    <div key={msg.id} style={{ background: '#0f172a', padding: 18, borderRadius: 8, border: '1px solid #991b1b' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                        <span style={{ fontWeight: 600, color: '#fca5a5' }}>{msg.subject || msg.title}</span>
                        <span style={{ fontSize: 12, color: '#94a3b8' }}>{new Date(msg.dispatchedAt || msg.deliveredAt).toLocaleTimeString()}</span>
                      </div>
                      <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 12 }}>
                        Recipient: <strong style={{ color: '#f8fafc' }}>{msg.to}</strong> | Latency: <strong style={{ color: '#10b981' }}>{msg.deliveryLatencyMs || 0}ms</strong>
                      </div>
                      <pre style={{ background: '#1e293b', padding: 12, borderRadius: 6, fontSize: 12, whiteSpace: 'pre-wrap', color: '#cbd5e1', marginBottom: 14 }}>
                        {msg.body || msg.message}
                      </pre>
                      {msg.actionToken && (
                        <div style={{ display: 'flex', gap: 10 }}>
                          <button
                            onClick={() => handleFeedback(msg.actionToken, 'confirmed_me')}
                            style={{ background: '#059669', color: '#fff', border: 'none', padding: '6px 14px', fontSize: 13 }}
                          >
                            ✓ This was me
                          </button>
                          <button
                            onClick={() => handleFeedback(msg.actionToken, 'reported_hijack')}
                            style={{ background: '#dc2626', color: '#fff', border: 'none', padding: '6px 14px', fontSize: 13 }}
                          >
                            ✗ This was NOT me
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Real-time HTTP Traffic & Decision Stream */}
        <div>
          <div style={{ background: 'var(--bg-card)', padding: 20, borderRadius: 12, border: '1px solid var(--border-color)', height: '100%' }}>
            <h3 style={{ fontSize: 16, marginBottom: 14, color: '#38bdf8' }}>Live Request Traffic Log</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 520, overflowY: 'auto' }}>
              {logs.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: 13 }}>No requests logged yet.</div>
              ) : (
                logs.map(log => {
                  const isBlocked = log.status === 403 || log.status === 401;
                  const isStepUp = log.status === 428;
                  const badgeColor = isBlocked ? '#ef4444' : isStepUp ? '#f59e0b' : '#10b981';

                  return (
                    <div key={log.id} style={{ background: '#0f172a', padding: '10px 12px', borderRadius: 6, borderLeft: `3px solid ${badgeColor}`, fontSize: 13 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span style={{ fontWeight: 600, color: '#f8fafc' }}>{log.method} {log.path}</span>
                        <span style={{ color: badgeColor, fontWeight: 700 }}>{log.status}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', fontSize: 12 }}>
                        <span>Decision: <strong style={{ color: badgeColor }}>{log.decision}</strong></span>
                        <span>Score: {log.score}</span>
                        <span>{log.durationMs}ms</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

