# ADR 0002: Hetzner Cloud as Initial Provider

## Status

Accepted

## Context

Devbox needs a cloud provider for provisioning development servers. The major options include:

- AWS EC2
- Google Cloud Compute Engine
- Microsoft Azure VMs
- DigitalOcean Droplets
- Linode
- Hetzner Cloud
- Vultr

## Decision

Hetzner Cloud is the initial (and currently only) supported provider.

## Consequences

### Positive

- **Cost-effective**: Hetzner offers significantly lower prices than US hyperscalers (often 3-5x cheaper for equivalent specs)
- **European company**: German company with EU data centers, good for GDPR compliance
- **Simple API**: Clean, well-documented REST API with good CORS support
- **Hourly billing**: Pay only for actual usage, ideal for ephemeral dev environments
- **Good value specs**: Servers include generous bandwidth and fast NVMe storage

### Negative

- **Limited to Hetzner users**: Users must have a Hetzner account
- **Fewer regions**: Primarily EU and US data centers (no Asia-Pacific)
- **Less ecosystem**: Fewer managed services compared to AWS/GCP

### Neutral

- **Provider lock-in**: Cloud-init scripts are somewhat portable, but the UI is Hetzner-specific

## Future Considerations

The architecture allows adding additional providers. Each would require:

1. A new API client module (like `hetzner.js`)
2. Provider selection in the UI
3. Provider-specific configuration options

Likely candidates for future support:

- DigitalOcean (similar API simplicity)
- Vultr (good value)
- AWS EC2 (enterprise users)

## Alternatives Considered

### AWS EC2

Most popular but:

- More expensive for dev workloads
- Complex IAM and networking setup
- Overkill for ephemeral dev environments

### DigitalOcean

Good alternative, similar simplicity to Hetzner:

- Slightly more expensive
- Better US presence
- Could be added as a second provider

### Multi-Provider from Day One

Rejected to reduce initial complexity. Better to validate the concept with one provider first.
