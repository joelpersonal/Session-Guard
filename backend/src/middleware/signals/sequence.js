/**
 * Signal f_Q: Request-sequence plausibility against bounded recent history window
 * Output: [0.0, 1.0]
 * Uses a clean, deterministic hand-written rule set.
 */

const SENSITIVE_PATHS = [
  '/api/sensitive/change-password',
  '/api/sensitive/disable-mfa',
  '/api/sensitive/recovery-email',
  '/api/sensitive/payment-details'
];

function extractSequenceSignal(currentPath, currentMethod, baseline) {
  if (!baseline) return 0.0;
  
  const history = baseline.requestHistory || [];
  let penalty = 0.0;

  const isSensitive = SENSITIVE_PATHS.some(p => currentPath.startsWith(p));

  // Rule 1: Cold sensitive action (jumping straight to sensitive action on 0 or 1 request history)
  if (isSensitive) {
    if (history.length === 0) {
      penalty += 0.85; // immediate attack heuristic
    } else {
      // Check if user has visited any benign user / settings / dashboard page before this sensitive action
      const hasViewedPrerequisite = history.some(req => 
        req.path.startsWith('/api/user') || 
        req.path.startsWith('/dashboard') || 
        req.path.startsWith('/settings')
      );
      if (!hasViewedPrerequisite) {
        penalty += 0.65;
      }
    }

    // Rule 2: Rapid successive sensitive actions (stolen token automation)
    const recentSensitive = history.slice(-3).filter(req => 
      SENSITIVE_PATHS.some(p => req.path.startsWith(p))
    );
    if (recentSensitive.length >= 2) {
      penalty += 0.70;
    }
  }

  // Rule 3: POST/PUT without any preceding GET in recent history
  if ((currentMethod === 'POST' || currentMethod === 'PUT') && history.length > 0) {
    const recentGets = history.slice(-5).filter(req => req.method === 'GET');
    if (recentGets.length === 0) {
      penalty += 0.40;
    }
  }

  return Math.min(1.0, penalty);
}

/**
 * Record current request into bounded sliding history window (last 20 requests)
 */
function updateSequenceHistory(baseline, path, method, timestamp) {
  if (!baseline.requestHistory) {
    baseline.requestHistory = [];
  }
  baseline.requestHistory.push({ path, method, timestamp });
  if (baseline.requestHistory.length > 20) {
    baseline.requestHistory.shift();
  }
}

module.exports = {
  extractSequenceSignal,
  updateSequenceHistory,
  SENSITIVE_PATHS
};

