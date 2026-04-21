export function normalizeDomainInput(input) {
  const raw = String(input || '').trim();
  if (!raw) return '';
  const withoutProtocol = raw.replace(/^https?:\/\//i, '');
  const hostOnly = withoutProtocol.split('/')[0].trim().toLowerCase();
  return hostOnly;
}

export function formatSiteUrl(domain) {
  const normalized = normalizeDomainInput(domain);
  if (!normalized) return '';
  if (
    normalized.startsWith('localhost') ||
    normalized.startsWith('127.0.0.1') ||
    normalized.endsWith('.local')
  ) {
    return `http://${normalized}`;
  }
  return `https://${normalized}`;
}
