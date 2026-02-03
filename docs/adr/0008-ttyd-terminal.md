# ADR 0008: ttyd for Browser-Based Terminal

## Status

Accepted

## Context

Devbox provisions development servers that need to be accessible from a browser. Users need terminal access to:

- Run commands
- Use CLI tools (git, npm, etc.)
- Run Claude Code (the primary use case)

Options for browser-based terminal access:

1. **ttyd**: Lightweight terminal server, shares TTY over WebSocket
2. **Wetty**: Node.js-based web terminal
3. **GoTTY**: Go-based, similar to ttyd
4. **code-server**: VS Code in browser (includes terminal)
5. **Custom xterm.js + backend**: Build our own terminal service

## Decision

Use ttyd as the browser-based terminal solution.

## Consequences

### Positive

- **Works out of the box**: Single binary, minimal configuration
- **Lightweight**: Small resource footprint (~5MB binary)
- **Fast**: Written in C, efficient WebSocket handling
- **Shell-agnostic**: Works with any shell (bash, zsh, fish)
- **Themeable**: Supports terminal color schemes
- **Authentication**: Built-in basic auth and token-based auth
- **Active maintenance**: Regular updates and security fixes

### Negative

- **Single session**: Default is one terminal per connection (can be configured)
- **No file browser**: Just terminal, no integrated file management
- **External dependency**: Requires installation during provisioning

### Neutral

- **Multiplexing**: Can run tmux/zellij inside ttyd for multiple panes

## Implementation

ttyd is installed and configured via cloud-init:

```yaml
packages:
  - ttyd

write_files:
  - path: /etc/systemd/system/ttyd.service
    content: |
      [Service]
      ExecStart=/usr/bin/ttyd -W -t fontSize=14 tmux new -A -s main

runcmd:
  - systemctl enable --now ttyd
```

Caddy reverse proxy provides HTTPS:

```
terminal.example.com {
    reverse_proxy localhost:7681
}
```

### Theme Integration

ttyd supports xterm.js themes. Devbox generates theme configuration that matches the selected UI theme, providing visual consistency between the web UI and terminal.

## Alternatives Considered

### Wetty

Node.js web terminal:
- More resource-heavy (Node.js runtime)
- Similar functionality to ttyd
- Less commonly used

Rejected because ttyd is lighter and sufficient.

### GoTTY

Go-based terminal sharing:
- Similar to ttyd but less actively maintained
- Fewer configuration options

Rejected for lower activity and fewer features.

### code-server (VS Code in browser)

Full IDE with integrated terminal:
- Much heavier resource usage
- More complex setup
- Includes features we don't need

Rejected because Claude Code is the primary interface, not VS Code. ttyd provides just what's needed.

### Custom xterm.js Solution

Build a custom terminal backend:
- Maximum control
- But significant development effort
- Reinventing the wheel

Rejected because ttyd already does this well.
