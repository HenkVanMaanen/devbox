# ADR 0011: Claude Code as Primary Use Case

## Status

Accepted

## Context

Devbox needed a clear primary use case to guide design decisions. While cloud development environments have many potential uses, focusing on a specific workflow helps prioritize features and make tradeoffs.

Potential primary use cases:

1. **AI-assisted development with Claude Code**
2. **General remote development**
3. **Team collaboration/pair programming**
4. **CI/CD or testing environments**
5. **Learning/tutorials**

## Decision

Claude Code (Anthropic's CLI tool for AI-assisted coding) is the primary intended use case for Devbox. The application is designed around the workflow of:

1. Spin up a cheap, ephemeral cloud server
2. Connect via browser terminal
3. Use Claude Code for AI-assisted development
4. Delete the server at end of day

## Consequences

### Positive

- **Clear feature prioritization**: Terminal-first UI, API key configuration, theme sync
- **Focused UX**: Optimize for quick server creation and terminal access
- **Cost alignment**: Ephemeral servers match Claude Code's per-token cost model
- **Integration opportunities**: Theme synchronization, credential setup, pre-configuration

### Negative

- **Narrower appeal**: Users not using Claude Code may find features less relevant
- **Dependency on external tool**: Value proposition tied to Claude Code's capabilities

### Neutral

- **Still general-purpose**: Nothing prevents using Devbox for other development workflows

## Implementation

### Claude Code Configuration Section

The settings include a dedicated Claude Code section:

```javascript
{
  claude: {
    apiKey: 'sk-ant-...',           // Pre-configured API key
    enableTelemetry: false,          // Privacy preference
    enableNotifications: true,       // Desktop notifications
    skipPermissions: false,          // Auto-approve actions
  }
}
```

### Theme Synchronization

When provisioning a server, Devbox can generate Claude Code configuration that matches the selected theme:

- Terminal colors match web UI theme
- Claude Code respects the same color palette
- tmux/zellij configs also synchronized

### Workflow Optimization

The UI prioritizes the happy path:

1. **Dashboard**: Shows servers and quick-create form
2. **One-click provisioning**: Pre-selected profile creates server immediately
3. **Direct terminal link**: Click to open terminal in new tab
4. **Auto-delete option**: Server can be configured to delete after N hours

## Alternatives Considered

### General Remote Development

Compete with Gitpod, GitHub Codespaces, etc.:

- Larger market
- But more competition
- Less differentiation
- Would need more features (IDE integration, Git workflows)

Rejected because the market is crowded and requires more resources.

### Team/Enterprise Focus

Multi-user features, shared environments:

- Higher revenue potential
- But requires backend (authentication, access control)
- Contradicts zero-backend architecture

Rejected because it conflicts with core architectural decisions.

### No Specific Focus

General-purpose tool for any development:

- Maximum flexibility
- But unclear value proposition
- Harder to make design decisions

Rejected because focus helps make better tradeoffs.

## Future Considerations

While Claude Code is the primary use case, Devbox remains useful for:

- General terminal-based development
- Testing configurations before deploying to production servers
- Learning Linux/cloud administration
- Running automated tasks

These secondary use cases can be supported without compromising the primary focus.
