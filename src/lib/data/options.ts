// Shared dropdown options used across Config and ProfileEdit pages

export const dnsServices = [
  { value: 'sslip.io', label: 'sslip.io', description: 'Wildcard DNS for any IP' },
  { value: 'nip.io', label: 'nip.io', description: 'Dead simple wildcard DNS' },
  { value: 'traefik.me', label: 'traefik.me', description: 'Traefik project DNS (less common)' },
  { value: 'custom', label: 'Custom domain', description: 'Your domain delegated to sslip.io' },
] as const;

export const acmeProviders = [
  { value: 'zerossl', label: 'ZeroSSL', description: 'No rate limits, recommended for testing' },
  { value: 'letsencrypt', label: "Let's Encrypt", description: 'Most popular CA' },
  { value: 'buypass', label: 'Buypass', description: 'Norwegian CA' },
  { value: 'actalis', label: 'Actalis', description: 'Italian CA' },
  { value: 'custom', label: 'Custom ACME', description: 'Self-hosted or other CA' },
] as const;
