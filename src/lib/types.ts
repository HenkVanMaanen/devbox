// Core type definitions for Devbox

export interface SSHKey {
  name: string;
  pubKey: string;
}

export interface GitCredential {
  host: string;
  username: string;
  token: string;
}

export interface EnvVar {
  name: string;
  value: string;
}

export interface HetznerConfig {
  serverType: string;
  location: string;
  baseImage: string;
}

export interface ServicesConfig {
  codeServer: boolean;
  claudeTerminal: boolean;
  shellTerminal: boolean;
  accessToken: string;
  dnsService: 'sslip.io' | 'nip.io' | 'traefik.me' | 'custom';
  customDnsDomain: string;
  acmeProvider: 'zerossl' | 'letsencrypt' | 'buypass' | 'actalis' | 'custom';
  acmeEmail: string;
  zerosslEabKeyId: string;
  zerosslEabKey: string;
  actalisEabKeyId: string;
  actalisEabKey: string;
  customAcmeUrl: string;
  customEabKeyId: string;
  customEabKey: string;
}

export interface PackagesConfig {
  mise: string[];
  apt: string[];
}

export interface AutoDeleteConfig {
  enabled: boolean;
  timeoutMinutes: number;
  warningMinutes: number;
}

export interface ClaudeConfig {
  apiKey: string;
  settings: string;
  credentialsJson: Record<string, unknown> | null;
  theme: '' | 'dark' | 'light' | 'dark-daltonized' | 'light-daltonized';
  skipPermissions: boolean;
}

export interface ShellConfig {
  default: 'fish' | 'zsh' | 'bash';
  starship: boolean;
}

export interface GlobalConfig {
  ssh: {
    keys: SSHKey[];
  };
  git: {
    userName: string;
    userEmail: string;
    credentials: GitCredential[];
  };
  shell: ShellConfig;
  services: ServicesConfig;
  hetzner: HetznerConfig;
  autoDelete: AutoDeleteConfig;
  claude: ClaudeConfig;
  packages: PackagesConfig;
  repos: string[];
  envVars: EnvVar[];
}

export interface Profile {
  id: string;
  name: string;
  overrides: Record<string, unknown>;
}

export interface Profiles {
  [id: string]: Profile;
}

export interface Server {
  id: number;
  name: string;
  status: 'running' | 'starting' | 'stopping' | 'off' | 'initializing' | 'migrating' | 'rebuilding' | 'deleting' | 'unknown';
  public_net: {
    ipv4: { ip: string };
    ipv6: { ip: string };
  };
  server_type: {
    name: string;
    description: string;
    cores: number;
    memory: number;
    disk: number;
  };
  datacenter: {
    name: string;
    location: {
      city: string;
      country: string;
    };
  };
  created: string;
  labels: Record<string, string>;
}

export interface ServerType {
  id: number;
  name: string;
  description: string;
  cores: number;
  memory: number;
  disk: number;
  prices: Array<{
    location: string;
    price_hourly: { gross: string };
    price_monthly: { gross: string };
  }>;
}

export interface Location {
  id: number;
  name: string;
  description: string;
  country: string;
  city: string;
}

export interface Image {
  id: number;
  name: string;
  description: string;
  type: 'system' | 'snapshot' | 'backup' | 'app';
  os_flavor: string;
  os_version: string;
}

export interface Toast {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info';
}
