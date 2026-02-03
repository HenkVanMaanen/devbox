# ADR 0006: Two-Level Configuration Hierarchy

## Status

Accepted

## Context

Users need to configure many settings for their development servers:

- SSH keys
- Git credentials
- Packages to install
- Shell preferences
- Services to run
- Editor/IDE settings

Different projects or use cases may need different configurations. For example:
- A Node.js project needs different packages than a Python project
- A client project might need different Git credentials than personal work
- Experimentation might need minimal config, production-like work needs full setup

## Decision

Implement a two-level configuration hierarchy:

1. **Global Config**: Default settings that apply to all servers
2. **Profiles**: Named configurations that can override specific global settings

When generating cloud-init, profile settings are deeply merged over global settings.

## Consequences

### Positive

- **Flexibility**: Customize per-project without duplicating common settings
- **DRY**: Shared settings (SSH keys, email) defined once in global config
- **Quick switching**: Change entire configuration by selecting a different profile
- **Experimentation**: Create minimal profiles for testing without affecting main setup

### Negative

- **Complexity**: Users must understand the inheritance model
- **Debugging**: May be unclear which level a setting comes from
- **UI complexity**: Need separate pages for global config and profile editing

### Neutral

- **Learning curve**: Power users will appreciate it; casual users can ignore profiles

## Implementation

`storage.js` handles the merge:

```javascript
export function getEffectiveConfig(profile) {
  const global = getGlobalConfig();
  if (!profile) return global;
  return deepMerge(global, profile.overrides);
}
```

The `deepMerge` function recursively combines objects, with profile values taking precedence.

### Example

Global config:
```json
{
  "ssh": { "keys": ["ssh-ed25519 AAAA..."] },
  "packages": { "apt": ["git", "curl"] },
  "shell": { "default": "zsh" }
}
```

Profile "nodejs" overrides:
```json
{
  "packages": { "mise": ["node@lts"] }
}
```

Effective config:
```json
{
  "ssh": { "keys": ["ssh-ed25519 AAAA..."] },
  "packages": { "apt": ["git", "curl"], "mise": ["node@lts"] },
  "shell": { "default": "zsh" }
}
```

## Alternatives Considered

### Flat Profiles Only

Each profile is completely independent:
- Simpler mental model
- But requires duplicating common settings across profiles
- Changes to shared settings must be made in every profile

Rejected because duplication leads to inconsistency.

### Unlimited Inheritance Chain

Profiles can inherit from other profiles:
- Maximum flexibility
- But complex to understand and debug
- Overkill for typical use cases

Rejected as over-engineering. Two levels covers the common cases.

### Template Strings

Global config with placeholders filled by profiles:
- Powerful but complex
- Harder to implement and maintain

Rejected for complexity reasons.
