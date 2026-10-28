const config = require('../../config');
const SessionManager = require('../../models/session');

/**
 * Signal f_C: Concurrent-token-use signal
 * Detects the same session/credential used from conflicting contexts within Delta (default 5s).
 * Alternating context (D1 -> D2 -> D1 -> D2) scores higher (1.0) than a single switch (0.55).
 * Output: [0.0, 1.0]
 */
function extractConcurrencySignal(currentIp, headers, currentTime, baseline, deltaWindowSec = config.thresholds.concurrencyWindowSec) {
  if (!baseline) return 0.0;

  const currentPrefix = SessionManager.extractIpPrefix(currentIp);
  const currentHash = SessionManager.hashClientHeaders(headers);
  const currentContextId = `${currentPrefix}__${currentHash}`;

  const deltaMs = deltaWindowSec * 1000;
  const history = baseline.contextHistory || [];

  // Filter history within the sliding Delta window
  const recentHistory = history.filter(item => (currentTime - item.timestamp) <= deltaMs);

  if (recentHistory.length === 0) {
    return 0.0;
  }

  // Check if any conflicting context exists in recent window
  const conflictingContexts = recentHistory.filter(item => item.contextId !== currentContextId);

  if (conflictingContexts.length === 0) {
    // All recent requests were from the exact same context
    return 0.0;
  }

  // Count transitions/switches in the window
  const contextsSequence = [...recentHistory.map(h => h.contextId), currentContextId];
  let switches = 0;
  for (let i = 1; i < contextsSequence.length; i++) {
    if (contextsSequence[i] !== contextsSequence[i - 1]) {
      switches++;
    }
  }

  // Alternating context: multiple switches (e.g. D1 -> D2 -> D1 ...)
  if (switches >= 2) {
    return 1.0; // High confidence concurrency attack
  }

  // Single switch within tight Delta window
  return 0.55;
}

/**
 * Update baseline context history with current request
 */
function updateContextHistory(baseline, currentIp, headers, currentTime, deltaWindowSec = config.thresholds.concurrencyWindowSec) {
  if (!baseline.contextHistory) {
    baseline.contextHistory = [];
  }

  const currentPrefix = SessionManager.extractIpPrefix(currentIp);
  const currentHash = SessionManager.hashClientHeaders(headers);
  const currentContextId = `${currentPrefix}__${currentHash}`;

  baseline.contextHistory.push({
    contextId: currentContextId,
    ip: currentIp,
    ipPrefix: currentPrefix,
    headerHash: currentHash,
    timestamp: currentTime
  });

  const deltaMs = deltaWindowSec * 1000;
  // Retain items within 2 * deltaMs for safety
  baseline.contextHistory = baseline.contextHistory.filter(
    item => (currentTime - item.timestamp) <= (deltaMs * 2)
  );
}

module.exports = {
  extractConcurrencySignal,
  updateContextHistory
};

