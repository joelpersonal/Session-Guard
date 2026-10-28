/**
 * Signal f_T: Temporal consistency (burstiness / regularity vs. rhythm)
 * Output: [0.0, 1.0]
 * 0.0 - 0.2 = natural human pace with healthy variance
 * 0.6 - 0.8 = mechanical robotic periodicity
 * 0.8 - 1.0 = inhuman sub-50ms burst or extreme timing deviation
 */
function extractTemporalSignal(currentTime, baseline) {
  if (!baseline || !baseline.lastRequestAt) {
    return 0.0;
  }

  const deltaMs = Math.max(1, currentTime - baseline.lastRequestAt);

  // Inhuman burst detection (< 40ms is physically impossible for manual human click flow)
  if (deltaMs < 40) {
    return 1.0;
  }
  if (deltaMs < 80) {
    return 0.75;
  }

  const intervals = (baseline.timing && baseline.timing.intervals) || [];
  if (intervals.length < 3) {
    // Early in session, human interactive range is 150ms - 60,000ms
    if (deltaMs >= 150 && deltaMs <= 60000) {
      return 0.05;
    }
    return 0.2;
  }

  // Compute distribution statistics: mean & standard deviation
  const n = intervals.length;
  const mean = intervals.reduce((acc, val) => acc + val, 0) / n;
  const variance = intervals.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / n;
  const std = Math.sqrt(variance);

  // Check for robotic regularity (very low coefficient of variation, e.g. bot polling at fixed rate)
  const cv = std / (mean || 1);
  if (cv < 0.05 && intervals.length >= 5) {
    return 0.85; // highly unnatural fixed-cadence robot
  }

  // Check z-score deviation
  if (std > 0) {
    const zScore = Math.abs(deltaMs - mean) / std;
    if (zScore > 3.5) {
      return Math.min(1.0, 0.4 + (zScore - 3.5) * 0.15);
    }
  }

  // Natural human range
  return 0.0;
}

/**
 * Update baseline timing state with latest request
 */
function updateTimingState(baseline, currentTime) {
  if (!baseline.timing) {
    baseline.timing = { intervals: [], meanInterval: 0, varianceInterval: 0 };
  }

  if (baseline.lastRequestAt) {
    const deltaMs = currentTime - baseline.lastRequestAt;
    baseline.timing.intervals.push(deltaMs);
    // Keep bounded window of last 20 intervals
    if (baseline.timing.intervals.length > 20) {
      baseline.timing.intervals.shift();
    }
  }
  baseline.lastRequestAt = currentTime;
}

module.exports = {
  extractTemporalSignal,
  updateTimingState
};

