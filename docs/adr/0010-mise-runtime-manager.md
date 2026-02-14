# ADR 0010: mise for Runtime Version Management

## Status

Accepted

## Context

Development servers need various language runtimes:

- Node.js
- Python
- Go
- Rust
- Ruby
- And others

System packages often provide outdated versions. Developers need:

- Specific versions for project compatibility
- Easy switching between versions
- Consistent environment across machines

Options for runtime version management:

1. **mise** (formerly rtx): Fast, polyglot version manager
2. **asdf**: Original polyglot version manager
3. **Individual tools**: nvm, pyenv, rbenv, etc.
4. **System packages**: apt/dnf packages
5. **Docker**: Containerized runtimes

## Decision

Use mise as the runtime version manager for all languages.

## Consequences

### Positive

- **Fast**: Written in Rust, significantly faster than asdf
- **Easy setup**: Single tool for all languages
- **Minimal configuration**: Simple `.mise.toml` or `.tool-versions`
- **asdf-compatible**: Works with existing asdf plugins and `.tool-versions` files
- **Active development**: Regular updates, responsive maintainers
- **Good defaults**: Sensible behavior out of the box

### Negative

- **Newer tool**: Less established than asdf or individual managers
- **Learning curve**: Users familiar with nvm/pyenv need to learn mise
- **Plugin dependency**: Relies on plugin ecosystem for some languages

### Neutral

- **Shell integration**: Requires shell hook for automatic version switching

## Implementation

mise is installed via cloud-init:

```yaml
runcmd:
  - curl https://mise.run | sh
  - echo 'eval "$(~/.local/bin/mise activate bash)"' >> /etc/profile.d/mise.sh
```

Runtimes are installed based on profile configuration:

```yaml
runcmd:
  - mise install node@lts
  - mise install python@3.12
  - mise use --global node@lts python@3.12
```

### Integration with Profiles

The Devbox UI allows selecting runtimes in profile configuration:

```javascript
{
  "packages": {
    "mise": ["node@lts", "python@3.12", "go@latest"]
  }
}
```

## Alternatives Considered

### asdf

The original polyglot version manager:

- Mature, widely used
- But slower (bash-based)
- mise is API-compatible anyway

Rejected because mise is faster with the same interface.

### Individual Tools (nvm, pyenv, rbenv)

Separate managers per language:

- More familiar to some users
- But inconsistent interfaces
- More setup complexity
- Harder to configure in cloud-init

Rejected for configuration complexity and inconsistency.

### System Packages

Use apt/dnf packages:

- Simplest installation
- But often outdated versions
- Harder to get specific versions
- Global only, no per-project versions

Rejected because version flexibility is important for development.

### Docker/Containers

Run runtimes in containers:

- Complete isolation
- But adds complexity
- Overkill for dev environment
- Poor integration with tools like Claude Code

Rejected because native runtimes are simpler for interactive development.
