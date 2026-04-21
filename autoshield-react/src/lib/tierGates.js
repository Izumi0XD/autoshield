export const PREMIUM_FEATURES = {
  customWafRules: { tier: 'premium', label: 'Custom WAF Rules' },
  geoBlocking: { tier: 'premium', label: 'Geographic IP Blocking' },
  rateLimitConfig: { tier: 'premium', label: 'Rate Limit Configuration' },
  webhookSiem: { tier: 'premium', label: 'Webhook & SIEM Integration' },
  advancedReports: { tier: 'premium', label: 'Advanced Report Generation' },
  unlimitedSites: { tier: 'premium', label: 'Unlimited Protected Sites' },
  ddosShield: { tier: 'premium', label: 'DDoS Shield Pro' },
  customAlerts: { tier: 'premium', label: 'Custom Alert Thresholds' },
  ipReputation: { tier: 'premium', label: 'IP Reputation Database' },
  priorityEdge: { tier: 'premium', label: 'Priority Edge Routing' },
};

export function normalizeTier(tier) {
  return tier === 'premium' ? 'premium' : 'free';
}

export function deriveTierFromUser(user) {
  if (!user || typeof user !== 'object') return 'free';
  return normalizeTier(user.tier);
}

export function featureGateForTier(tier, feature, features = PREMIUM_FEATURES) {
  const normalizedTier = normalizeTier(tier);
  const target = features[feature];
  if (!target) {
    return { allowed: true, label: feature };
  }
  return {
    allowed: normalizedTier === 'premium' || target.tier === 'free',
    label: target.label,
    tier: target.tier,
  };
}
