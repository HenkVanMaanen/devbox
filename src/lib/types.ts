// Core type definitions for Devbox — Zod schemas + inferred types

import { z } from 'zod';

import { isSafeObjectPath } from '$lib/utils/path-safety';

export const autoDeleteConfigSchema = z.object({
  enabled: z.boolean(),
  timeoutMinutes: z.number(),
  warningMinutes: z.number(),
});

export const chezmoiConfigSchema = z.object({
  ageKey: z.string(),
  repoUrl: z.string(),
});

export const customCloudInitConfigSchema = z.object({
  mode: z.enum(['merge', 'replace']),
  yaml: z.string(),
});
export type CustomCloudInitConfig = z.infer<typeof customCloudInitConfigSchema>;

export const gitCredentialSchema = z.object({
  host: z.string(),
  token: z.string(),
  username: z.string(),
});
export type GitCredential = z.infer<typeof gitCredentialSchema>;

export const sshKeySchema = z.object({
  name: z.string(),
  pubKey: z.string(),
});

export const hetznerConfigSchema = z.object({
  baseImage: z.string(),
  location: z.string(),
  serverType: z.string(),
});

export const servicesConfigSchema = z.object({
  accessToken: z.string(),
  acmeEmail: z.string(),
  acmeProvider: z.enum(['actalis', 'buypass', 'custom', 'letsencrypt', 'zerossl']),
  actalisEabKey: z.string(),
  actalisEabKeyId: z.string(),
  customAcmeUrl: z.string(),
  customDnsDomain: z.string(),
  customEabKey: z.string(),
  customEabKeyId: z.string(),
  dnsService: z.enum(['custom', 'nip.io', 'sslip.io', 'traefik.me']),
  zerosslEabKey: z.string(),
  zerosslEabKeyId: z.string(),
});

export const globalConfigSchema = z.object({
  autoDelete: autoDeleteConfigSchema,
  chezmoi: chezmoiConfigSchema,
  customCloudInit: customCloudInitConfigSchema,
  git: z.object({
    credential: gitCredentialSchema,
  }),
  hetzner: hetznerConfigSchema,
  services: servicesConfigSchema,
  ssh: z.object({
    keys: z.array(sshKeySchema),
  }),
});
export type GlobalConfig = z.infer<typeof globalConfigSchema>;

// API response schemas use .loose() to allow extra fields from Hetzner API
export const imageSchema = z
  .object({
    description: z.string(),
    id: z.number(),
    name: z.string(),
    os_flavor: z.string(),
    os_version: z.string(),
    type: z.enum(['app', 'backup', 'snapshot', 'system']),
  })
  .loose();
export type Image = z.infer<typeof imageSchema>;

export const locationSchema = z
  .object({
    city: z.string(),
    country: z.string(),
    description: z.string(),
    id: z.number(),
    name: z.string(),
  })
  .loose();
export type Location = z.infer<typeof locationSchema>;

export const profileSchema = z.object({
  id: z.string(),
  name: z.string(),
  overrides: z.record(
    z.string().refine((path) => isSafeObjectPath(path), {
      message: 'Unsafe override path',
    }),
    z.unknown(),
  ),
});
export type Profile = z.infer<typeof profileSchema>;

export const profilesSchema = z.record(z.string(), profileSchema);
export type Profiles = z.infer<typeof profilesSchema>;

export const serverSchema = z
  .object({
    created: z.string(),
    datacenter: z
      .object({
        location: z.object({ city: z.string(), country: z.string() }).loose(),
        name: z.string(),
      })
      .loose(),
    id: z.number(),
    labels: z.record(z.string(), z.string()),
    name: z.string(),
    public_net: z
      .object({
        ipv4: z.object({ ip: z.string() }).loose(),
        ipv6: z.object({ ip: z.string() }).loose(),
      })
      .loose(),
    server_type: z
      .object({
        cores: z.number(),
        description: z.string(),
        disk: z.number(),
        memory: z.number(),
        name: z.string(),
      })
      .loose(),
    status: z.enum([
      'deleting',
      'initializing',
      'migrating',
      'off',
      'rebuilding',
      'running',
      'starting',
      'stopping',
      'unknown',
    ]),
  })
  .loose();
export type Server = z.infer<typeof serverSchema>;

export const serverTypeSchema = z
  .object({
    cores: z.number(),
    description: z.string(),
    disk: z.number(),
    id: z.number(),
    memory: z.number(),
    name: z.string(),
    prices: z.array(
      z
        .object({
          location: z.string(),
          price_hourly: z.object({ gross: z.string() }).loose(),
          price_monthly: z.object({ gross: z.string() }).loose(),
        })
        .loose(),
    ),
  })
  .loose();
export type ServerType = z.infer<typeof serverTypeSchema>;

export const toastSchema = z.object({
  id: z.string(),
  message: z.string(),
  type: z.enum(['error', 'info', 'success']),
});
export type Toast = z.infer<typeof toastSchema>;
