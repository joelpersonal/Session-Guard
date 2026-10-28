const SENSITIVE_ROUTES = [
  '/api/sensitive/change-password',
  '/api/sensitive/disable-mfa',
  '/api/sensitive/recovery-email',
  '/api/sensitive/payment-details'
];

/**
 * Signal f_A: Sensitive-action context
 * Flags requests to designated high-impact routes
 * Output: 1.0 if sensitive, 0.0 otherwise
 */
function extractSensitiveSignal(path, method = 'POST') {
  if (!path) return 0.0;
  
  // Sensitive actions are typically state-mutating (POST, PUT, DELETE, PATCH)
  const isMatch = SENSITIVE_ROUTES.some(route => path.startsWith(route));
  if (isMatch) {
    return 1.0;
  }
  return 0.0;
}

module.exports = {
  extractSensitiveSignal,
  SENSITIVE_ROUTES
};

