// Shared dropdown options used across Config and ProfileEdit pages

export const dnsServices = [
  { description: 'Wildcard DNS for any IP', label: 'sslip.io', value: 'sslip.io' },
  { description: 'Dead simple wildcard DNS', label: 'nip.io', value: 'nip.io' },
  { description: 'Traefik project DNS (less common)', label: 'traefik.me', value: 'traefik.me' },
  { description: 'Your domain delegated to sslip.io', label: 'Custom domain', value: 'custom' },
] as const;

export const acmeProviders = [
  { description: 'No rate limits, recommended for testing', label: 'ZeroSSL', value: 'zerossl' },
  { description: 'Most popular CA', label: "Let's Encrypt", value: 'letsencrypt' },
  { description: 'Norwegian CA', label: 'Buypass', value: 'buypass' },
  { description: 'Italian CA', label: 'Actalis', value: 'actalis' },
  { description: 'Self-hosted or other CA', label: 'Custom ACME', value: 'custom' },
] as const;
