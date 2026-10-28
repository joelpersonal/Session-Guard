const SessionManager = require('../../models/session');

/**
 * Signal f_N: Network consistency vs. baseline
 * Output: [0.0, 1.0]
 * 0.0 = exact network match
 * 0.4 = same /16 related subnet
 * 1.0 = completely different network
 */
function extractNetworkSignal(currentIp, baseline) {
  if (!baseline || !baseline.ip) {
    return 0.0;
  }

  const currentPrefix = SessionManager.extractIpPrefix(currentIp);
  const baselinePrefix = baseline.ipPrefix || SessionManager.extractIpPrefix(baseline.ip);

  // Exact prefix match (/24 for IPv4)
  if (currentPrefix === baselinePrefix) {
    return 0.0;
  }

  // Check /16 subnet match for IPv4
  const currentClean = currentIp.replace(/^::ffff:/, '');
  const baselineClean = baseline.ip.replace(/^::ffff:/, '');

  if (currentClean.includes('.') && baselineClean.includes('.')) {
    const p1 = currentClean.split('.');
    const p2 = baselineClean.split('.');
    if (p1[0] === p2[0] && p1[1] === p2[1]) {
      return 0.4; // related network / same ISP or campus
    }
  }

  return 1.0; // foreign network
}

module.exports = {
  extractNetworkSignal
};

