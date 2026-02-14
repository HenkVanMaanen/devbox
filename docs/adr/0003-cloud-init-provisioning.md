# ADR 0003: Cloud-Init for Server Provisioning

## Status

Accepted

## Context

When a new development server is created, it needs to be configured with:

- Development tools and packages
- User accounts and SSH keys
- Shell configuration
- Services (terminal, reverse proxy, etc.)
- Git credentials and dotfiles

Options for provisioning include:

1. **Cloud-init**: Industry-standard for cloud instance initialization
2. **Configuration management**: Ansible, Puppet, Chef, Salt
3. **Custom scripts**: SSH in after boot and run setup scripts
4. **Pre-built images**: Create custom VM images with everything installed

## Decision

Use cloud-init for all server provisioning. The browser generates cloud-init YAML that Hetzner injects into the server at boot time.

## Consequences

### Positive

- **Stateless**: No need for a backend to run Ansible or SSH into servers
- **Fast**: Server is ready when it finishes booting, no second-stage provisioning
- **Portable**: Cloud-init is supported by all major cloud providers
- **Declarative**: Configuration is a YAML document, easy to review and share
- **Atomic**: Either provisioning succeeds or fails completely, no partial states

### Negative

- **Size limit**: Hetzner limits user-data to 32KB (compressed)
- **No interactivity**: Cannot prompt for input during provisioning
- **Debugging difficulty**: Errors happen during boot, before SSH is available
- **One-shot**: Cloud-init runs once at first boot, not for ongoing configuration

### Neutral

- **Learning curve**: Cloud-init has specific YAML structure and module system

## Implementation Details

The cloud-init generator in `cloudinit.js`:

1. Collects configuration from global settings and active profile
2. Generates YAML using cloud-init's native modules where possible
3. Falls back to `runcmd` for complex setup (services, dotfiles)
4. Validates the output doesn't exceed 32KB
5. Provides a preview with size indicator

## Alternatives Considered

### Ansible via Backend

Would require:

- A backend server to run Ansible
- SSH key management
- Waiting for server boot before running playbooks

Rejected because it contradicts the zero-backend architecture.

### Pre-Built Images

Custom Hetzner snapshots with everything pre-installed:

- Faster boot times
- But requires maintaining images
- Less flexible for per-server customization

May be worth exploring for common configurations in the future.

### SSH Scripts After Boot

Run scripts via SSH after the server is accessible:

- Maximum flexibility
- But requires a backend to initiate SSH
- Slower overall provisioning time

Rejected for same reasons as Ansible.
