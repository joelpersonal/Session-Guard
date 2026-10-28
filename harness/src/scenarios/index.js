const {
  sleep,
  loginUser,
  sendGuardedRequest,
  UA_DESKTOP_CHROME,
  UA_MOBILE_SAFARI,
  UA_ATTACKER_PYTHON,
  UA_ATTACKER_CURL,
  IP_PRIMARY,
  IP_MOBILE_SWITCH,
  IP_ATTACKER_FOREIGN,
  IP_ATTACKER_SAME_SUBNET
} = require('./common');

/**
 * S1: Normal session (no anomalies)
 * Ground Truth: Benign
 */
async function runS1(baseUrl, account, mode) {
  const login = await loginUser(baseUrl, account, IP_PRIMARY, UA_DESKTOP_CHROME);
  if (login.status !== 200) throw new Error('Login failed for S1');

  await sleep(60);
  const r1 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/profile', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  await sleep(60);
  const r2 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/dashboard', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  await sleep(60);
  const r3 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/settings', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  const blocked = [r1, r2, r3].some(r => r.status === 403 || r.decision === 'Terminate+Notify' || r.decision === 'Reject');
  const finalDecision = blocked ? 'Reject' : 'Allow';

  return {
    scenarioId: 'S1',
    scenarioName: 'Normal Session',
    groundTruth: 'benign',
    mode,
    decision: finalDecision,
    isCorrect: !blocked,
    detectionLatencyMs: null,
    timeToContainmentMs: null,
    notificationLatencyMs: null
  };
}

/**
 * S2: Legitimate network change mid-session
 * Ground Truth: Benign
 */
async function runS2(baseUrl, account, mode) {
  const login = await loginUser(baseUrl, account, IP_PRIMARY, UA_MOBILE_SAFARI);
  if (login.status !== 200) throw new Error('Login failed for S2');

  await sleep(60);
  const r1 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/profile', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_MOBILE_SAFARI, mode
  });

  // Switch network (Wi-Fi to LTE mobile data)
  await sleep(60);
  const r2 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/dashboard', {
    sessionId: login.sessionId, ip: IP_MOBILE_SWITCH, ua: UA_MOBILE_SAFARI, mode
  });

  await sleep(60);
  const r3 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/settings', {
    sessionId: login.sessionId, ip: IP_MOBILE_SWITCH, ua: UA_MOBILE_SAFARI, mode
  });

  const blocked = [r2, r3].some(r => r.status === 403 || r.decision === 'Terminate+Notify' || r.decision === 'Reject');
  const finalDecision = blocked ? 'Reject' : 'Allow';

  return {
    scenarioId: 'S2',
    scenarioName: 'Legitimate Network Change',
    groundTruth: 'benign',
    mode,
    decision: finalDecision,
    isCorrect: !blocked, // FP if blocked!
    detectionLatencyMs: blocked ? r2.detectionLatencyMs : null,
    timeToContainmentMs: blocked ? r2.timeToContainmentMs : null,
    notificationLatencyMs: blocked ? r2.notificationLatencyMs : null
  };
}

/**
 * S3: Stolen credential replayed from different network + different client headers (A1)
 * Ground Truth: Attack
 */
async function runS3(baseUrl, account, mode) {
  const login = await loginUser(baseUrl, account, IP_PRIMARY, UA_DESKTOP_CHROME);
  if (login.status !== 200) throw new Error('Login failed for S3');

  await sleep(60);
  // Attacker replays from foreign IP & Python UA
  const attackerReq = await sendGuardedRequest(baseUrl, 'GET', '/api/user/dashboard', {
    sessionId: login.sessionId,
    ip: IP_ATTACKER_FOREIGN,
    ua: UA_ATTACKER_PYTHON,
    mode
  });

  const isDetected = attackerReq.status === 403 || attackerReq.decision === 'Terminate+Notify' || attackerReq.decision === 'Reject' || attackerReq.decision === 'Step-Up';
  const finalDecision = attackerReq.decision;

  return {
    scenarioId: 'S3',
    scenarioName: 'Stolen Credential: Foreign Network + Foreign UA (A1)',
    groundTruth: 'attack',
    mode,
    decision: finalDecision,
    isCorrect: isDetected, // TP if detected
    detectionLatencyMs: isDetected ? attackerReq.detectionLatencyMs : null,
    timeToContainmentMs: isDetected ? attackerReq.timeToContainmentMs : null,
    notificationLatencyMs: isDetected ? attackerReq.notificationLatencyMs : null
  };
}

/**
 * S4: Stolen credential replayed from SAME network, spoofed headers matching victim (A2)
 * Ground Truth: Attack
 */
async function runS4(baseUrl, account, mode) {
  const login = await loginUser(baseUrl, account, IP_PRIMARY, UA_DESKTOP_CHROME);
  if (login.status !== 200) throw new Error('Login failed for S4');

  await sleep(60);
  await sendGuardedRequest(baseUrl, 'GET', '/api/user/profile', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  // Sophisticated adversary on same network with spoofed UA performs sudden sequence jump straight to sensitive action
  // with sub-30ms automated burst timing
  await sleep(10);
  const attackerReq = await sendGuardedRequest(baseUrl, 'POST', '/api/sensitive/recovery-email', {
    sessionId: login.sessionId,
    ip: IP_ATTACKER_SAME_SUBNET,
    ua: UA_DESKTOP_CHROME,
    body: { recoveryEmail: 'attacker-exfil@evil-domain.com' },
    mode
  });

  const isDetected = attackerReq.status === 403 || attackerReq.decision === 'Terminate+Notify' || attackerReq.decision === 'Reject' || attackerReq.decision === 'Step-Up';
  const finalDecision = attackerReq.decision;

  return {
    scenarioId: 'S4',
    scenarioName: 'Stolen Credential: Same Network + Spoofed UA (A2)',
    groundTruth: 'attack',
    mode,
    decision: finalDecision,
    isCorrect: isDetected,
    detectionLatencyMs: isDetected ? attackerReq.detectionLatencyMs : null,
    timeToContainmentMs: isDetected ? attackerReq.timeToContainmentMs : null,
    notificationLatencyMs: isDetected ? attackerReq.notificationLatencyMs : null
  };
}

/**
 * S5: Concurrent interleaved use of one credential from two contexts (D1 -> D2 -> D1 -> D2)
 * Ground Truth: Attack
 */
async function runS5(baseUrl, account, mode) {
  const login = await loginUser(baseUrl, account, IP_PRIMARY, UA_DESKTOP_CHROME);
  if (login.status !== 200) throw new Error('Login failed for S5');

  // Interleaved execution within Delta = 5s
  const r1 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/profile', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  await sleep(15);
  const r2 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/dashboard', {
    sessionId: login.sessionId, ip: IP_MOBILE_SWITCH, ua: UA_MOBILE_SAFARI, mode
  });

  await sleep(15);
  const r3 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/settings', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  await sleep(15);
  const r4 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/profile', {
    sessionId: login.sessionId, ip: IP_MOBILE_SWITCH, ua: UA_MOBILE_SAFARI, mode
  });

  const detectedReq = [r2, r3, r4].find(r => r.status === 403 || r.status === 428 || r.decision === 'Terminate+Notify' || r.decision === 'Reject' || r.decision === 'Step-Up');
  const isDetected = !!detectedReq;
  const finalDecision = isDetected ? detectedReq.decision : 'Allow';

  return {
    scenarioId: 'S5',
    scenarioName: 'Concurrent Interleaved Credential Use',
    groundTruth: 'attack',
    mode,
    decision: finalDecision,
    isCorrect: isDetected,
    detectionLatencyMs: isDetected ? detectedReq.detectionLatencyMs : null,
    timeToContainmentMs: isDetected ? detectedReq.timeToContainmentMs : null,
    notificationLatencyMs: isDetected ? detectedReq.notificationLatencyMs : null
  };
}

/**
 * S6: Sensitive action performed from anomalous context
 * Ground Truth: Attack
 */
async function runS6(baseUrl, account, mode) {
  const login = await loginUser(baseUrl, account, IP_PRIMARY, UA_DESKTOP_CHROME);
  if (login.status !== 200) throw new Error('Login failed for S6');

  await sleep(60);
  const req = await sendGuardedRequest(baseUrl, 'POST', '/api/sensitive/recovery-email', {
    sessionId: login.sessionId,
    ip: IP_ATTACKER_FOREIGN,
    ua: UA_ATTACKER_PYTHON,
    body: { recoveryEmail: 'attacker-exfil@evil-domain.com' },
    mode
  });

  const isDetected = req.status === 403 || req.decision === 'Terminate+Notify' || req.decision === 'Reject';
  const finalDecision = req.decision;

  return {
    scenarioId: 'S6',
    scenarioName: 'Sensitive Action from Anomalous Context',
    groundTruth: 'attack',
    mode,
    decision: finalDecision,
    isCorrect: isDetected,
    detectionLatencyMs: isDetected ? req.detectionLatencyMs : null,
    timeToContainmentMs: isDetected ? req.timeToContainmentMs : null,
    notificationLatencyMs: isDetected ? req.notificationLatencyMs : null
  };
}

/**
 * S7: Legitimate sensitive action, no anomaly (False-Positive check)
 * Ground Truth: Benign
 */
async function runS7(baseUrl, account, mode) {
  const login = await loginUser(baseUrl, account, IP_PRIMARY, UA_DESKTOP_CHROME);
  if (login.status !== 200) throw new Error('Login failed for S7');

  await sleep(60);
  await sendGuardedRequest(baseUrl, 'GET', '/api/user/profile', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  await sleep(60);
  await sendGuardedRequest(baseUrl, 'GET', '/api/user/dashboard', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  await sleep(60);
  await sendGuardedRequest(baseUrl, 'GET', '/api/user/settings', {
    sessionId: login.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  // Legitimate sensitive action with prior sequence, matching IP & UA
  await sleep(60);
  const req = await sendGuardedRequest(baseUrl, 'POST', '/api/sensitive/recovery-email', {
    sessionId: login.sessionId,
    ip: IP_PRIMARY,
    ua: UA_DESKTOP_CHROME,
    body: { recoveryEmail: 'verified-backup@example.com' },
    mode
  });

  const isBlocked = req.status === 403 || req.decision === 'Terminate+Notify' || req.decision === 'Reject';
  const finalDecision = isBlocked ? req.decision : 'Allow';

  return {
    scenarioId: 'S7',
    scenarioName: 'Legitimate Sensitive Action (Benign)',
    groundTruth: 'benign',
    mode,
    decision: finalDecision,
    isCorrect: !isBlocked,
    detectionLatencyMs: isBlocked ? req.detectionLatencyMs : null,
    timeToContainmentMs: isBlocked ? req.timeToContainmentMs : null,
    notificationLatencyMs: isBlocked ? req.notificationLatencyMs : null
  };
}

/**
 * S8: Legitimate multi-device use, sequential not interleaved (False-Positive check)
 * Ground Truth: Benign
 */
async function runS8(baseUrl, account, mode) {
  // 1. Device 1 (Laptop)
  const login1 = await loginUser(baseUrl, account, IP_PRIMARY, UA_DESKTOP_CHROME);
  if (login1.status !== 200) throw new Error('Login 1 failed for S8');

  await sleep(60);
  await sendGuardedRequest(baseUrl, 'GET', '/api/user/dashboard', {
    sessionId: login1.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  // Logout
  await sleep(60);
  await sendGuardedRequest(baseUrl, 'POST', '/api/auth/logout', {
    sessionId: login1.sessionId, ip: IP_PRIMARY, ua: UA_DESKTOP_CHROME, mode
  });

  // 2. Device 2 (Phone) - sequential valid new session
  await sleep(60);
  const login2 = await loginUser(baseUrl, account, IP_MOBILE_SWITCH, UA_MOBILE_SAFARI);
  if (login2.status !== 200) throw new Error('Login 2 failed for S8');

  await sleep(60);
  const r2 = await sendGuardedRequest(baseUrl, 'GET', '/api/user/dashboard', {
    sessionId: login2.sessionId, ip: IP_MOBILE_SWITCH, ua: UA_MOBILE_SAFARI, mode
  });

  const isBlocked = r2.status === 403 || r2.decision === 'Terminate+Notify' || r2.decision === 'Reject';
  const finalDecision = isBlocked ? r2.decision : 'Allow';

  return {
    scenarioId: 'S8',
    scenarioName: 'Legitimate Multi-Device Sequential (Benign)',
    groundTruth: 'benign',
    mode,
    decision: finalDecision,
    isCorrect: !isBlocked,
    detectionLatencyMs: isBlocked ? r2.detectionLatencyMs : null,
    timeToContainmentMs: isBlocked ? r2.timeToContainmentMs : null,
    notificationLatencyMs: isBlocked ? r2.notificationLatencyMs : null
  };
}

const SCENARIOS = [
  { id: 'S1', fn: runS1 },
  { id: 'S2', fn: runS2 },
  { id: 'S3', fn: runS3 },
  { id: 'S4', fn: runS4 },
  { id: 'S5', fn: runS5 },
  { id: 'S6', fn: runS6 },
  { id: 'S7', fn: runS7 },
  { id: 'S8', fn: runS8 }
];

module.exports = {
  SCENARIOS,
  runS1,
  runS2,
  runS3,
  runS4,
  runS5,
  runS6,
  runS7,
  runS8
};
