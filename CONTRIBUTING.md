# Contributing to Devbox

Thank you for your interest in contributing to Devbox!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/devbox.git`
3. Install dependencies: `npm install`
4. Create a branch: `git checkout -b feature/your-feature`

## Development Setup

```bash
npm install    # Install dependencies
npm run dev    # Start dev server with hot reload
npm test       # Run tests
```

## Before Submitting

### Run Tests

```bash
npm test
```

All tests must pass before submitting a PR.

### Check Code Style

- Use ES Modules (import/export)
- Use `const` over `let` where possible
- Follow existing naming conventions (see AGENTS.md)

### Security Checklist

- [ ] User input is escaped with `escapeHtml()` or `escapeAttr()`
- [ ] Shell commands use `shellEscape()` for user values
- [ ] No hardcoded secrets or credentials
- [ ] No new `unsafe-inline` in CSP

## Pull Request Process

1. **Create a descriptive PR title** using conventional commits:
   - `feat: Add new feature`
   - `fix: Fix bug in X`
   - `docs: Update documentation`

2. **Fill out the PR template** with:
   - Summary of changes
   - Testing performed
   - Screenshots (for UI changes)

3. **Keep PRs focused** - one feature or fix per PR

4. **Update documentation** if you change behavior

5. **Add tests** for new functionality

## What to Contribute

### Good First Issues

Look for issues labeled `good first issue` - these are suitable for newcomers.

### Feature Requests

Before implementing a large feature:

1. Check existing issues to avoid duplicates
2. Open an issue to discuss the approach
3. Wait for feedback before investing significant time

### Bug Fixes

1. Create an issue describing the bug (if one doesn't exist)
2. Reference the issue in your PR
3. Add a test that reproduces the bug

## Code Review

All PRs require review before merging. Reviewers will check:

- Code quality and style
- Test coverage
- Security implications
- Documentation updates

## Architecture Decisions

For significant changes, consider adding an ADR (Architecture Decision Record):

1. Create `docs/adr/XXXX-title.md`
2. Use the template in `docs/adr/README.md`
3. Explain context, decision, and consequences

## Questions?

- Open a GitHub issue for questions
- Check existing documentation in `docs/`
- Read the ADRs for architectural context

## Code of Conduct

Be respectful and constructive. We're all here to build something useful together.
