// Core type definitions for Devbox

export interface AutoDeleteConfig {
  enabled: boolean;
  timeoutMinutes: number;
  warningMinutes: number;
}

export interface ChezmoiConfig {
  ageKey: string;
  repoUrl: string;
}

export interface CustomCloudInitConfig {
  mode: 'merge' | 'replace';
  yaml: string;
}

export interface GitCredential {
  host: string;
  token: string;
  username: string;
}

export interface GlobalConfig {
  autoDelete: AutoDeleteConfig;
  chezmoi: ChezmoiConfig;
  customCloudInit: CustomCloudInitConfig;
  git: {
    credential: GitCredential;
  };
  hetzner: HetznerConfig;
  services: ServicesConfig;
  ssh: {
    keys: SSHKey[];
  };
}

export interface HetznerConfig {
  baseImage: string;
  location: string;
  serverType: string;
}

export interface Image {
  description: string;
  id: number;
  name: string;
  os_flavor: string;
  os_version: string;
  type: 'app' | 'backup' | 'snapshot' | 'system';
}

export interface Location {
  city: string;
  country: string;
  description: string;
  id: number;
  name: string;
}

export interface Profile {
  id: string;
  name: string;
  overrides: Record<string, unknown>;
}

export type Profiles = Record<string, Profile>;

export interface Server {
  created: string;
  datacenter: {
    location: {
      city: string;
      country: string;
    };
    name: string;
  };
  id: number;
  labels: Record<string, string>;
  name: string;
  public_net: {
    ipv4: { ip: string };
    ipv6: { ip: string };
  };
  server_type: {
    cores: number;
    description: string;
    disk: number;
    memory: number;
    name: string;
  };
  status:
    | 'deleting'
    | 'initializing'
    | 'migrating'
    | 'off'
    | 'rebuilding'
    | 'running'
    | 'starting'
    | 'stopping'
    | 'unknown';
}

export interface ServerType {
  cores: number;
  description: string;
  disk: number;
  id: number;
  memory: number;
  name: string;
  prices: {
    location: string;
    price_hourly: { gross: string };
    price_monthly: { gross: string };
  }[];
}

export interface ServicesConfig {
  accessToken: string;
  acmeEmail: string;
  acmeProvider: 'actalis' | 'buypass' | 'custom' | 'letsencrypt' | 'zerossl';
  actalisEabKey: string;
  actalisEabKeyId: string;
  customAcmeUrl: string;
  customDnsDomain: string;
  customEabKey: string;
  customEabKeyId: string;
  dnsService: 'custom' | 'nip.io' | 'sslip.io' | 'traefik.me';
  zerosslEabKey: string;
  zerosslEabKeyId: string;
}

export interface SSHKey {
  name: string;
  pubKey: string;
}

export interface Toast {
  id: string;
  message: string;
  type: 'error' | 'info' | 'success';
}
