// Shared dropdown options used across Config and ProfileEdit pages

export const shellOptions = [
  { value: 'fish', label: 'Fish', description: 'Modern, user-friendly shell' },
  { value: 'zsh', label: 'Zsh', description: 'Extended Bourne shell' },
  { value: 'bash', label: 'Bash', description: 'GNU Bourne-Again shell' },
] as const;

export const dnsServices = [
  { value: 'sslip.io', label: 'sslip.io', description: 'Wildcard DNS for any IP' },
  { value: 'nip.io', label: 'nip.io', description: 'Dead simple wildcard DNS' },
] as const;

export const acmeProviders = [
  { value: 'zerossl', label: 'ZeroSSL', description: 'No rate limits, recommended for testing' },
  { value: 'letsencrypt', label: "Let's Encrypt", description: 'Most popular CA' },
  { value: 'buypass', label: 'Buypass', description: 'Norwegian CA' },
  { value: 'actalis', label: 'Actalis', description: 'Italian CA' },
  { value: 'custom', label: 'Custom ACME', description: 'Self-hosted or other CA' },
] as const;

export const claudeThemes = [
  { value: '', label: 'Default', description: 'System default' },
  { value: 'dark', label: 'Dark', description: 'Dark theme' },
  { value: 'light', label: 'Light', description: 'Light theme' },
  { value: 'dark-daltonized', label: 'Dark (Daltonized)', description: 'Color blind friendly dark' },
  { value: 'light-daltonized', label: 'Light (Daltonized)', description: 'Color blind friendly light' },
] as const;
