# Contributing to Kerb-Sleuth

Thank you for your interest in contributing to Kerb-Sleuth! This document provides guidelines and instructions for contributing.

## Safety Policy

**Safety is our top priority.** All contributions must adhere to these principles:

1. **Offline-First**: The tool must operate offline by default
2. **Explicit Authorization**: Sensitive operations require `--i-am-authorized` flag
3. **No Exploit Code**: Do not add modules that directly exploit vulnerabilities
4. **Clear Warnings**: All potentially dangerous operations must have clear warnings

## Development Setup

1. Fork the repository
2. Clone your fork:
```bash
git clone https://github.com/yourusername/kerb-sleuth.git
cd kerb-sleuth
```

3. Install dependencies:
```bash
go mod download
```

4. Create a feature branch:
```bash
git checkout -b feature/your-feature-name
```

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] **Safety Review**: Changes don't compromise safety-by-default principle
- [ ] **Tests Pass**: `make test` runs successfully
- [ ] **Synthetic Data Only**: Tests use only synthetic data (no real credentials/hashes)
- [ ] **Documentation Updated**: README and comments reflect changes
- [ ] **No Sensitive Data**: No passwords, hashes, or real network addresses in code
- [ ] **Legal Compliance**: Changes don't enable unauthorized access
- [ ] **Error Handling**: Proper error handling with informative messages
- [ ] **Code Format**: Run `make fmt` before committing

## Testing Guidelines

### Unit Tests
- Write tests for all new functions
- Use synthetic/mock data only
- Place tests in `*_test.go` files
- Aim for >80% code coverage

### Integration Tests
- Test complete workflows
- Use the `simulate` command for test data
- Never use real AD data in tests

### CI Requirements
- All tests must pass in CI
- No network calls in tests
- Tests must be deterministic

## Code Style

### Go Standards
- Follow standard Go formatting (`gofmt`)
- Use meaningful variable names
- Keep functions small and focused
- Document exported functions

### Error Messages
- Be specific and actionable
- Include context
- Suggest fixes when possible

### Logging
- Use appropriate log levels
- Include relevant context
- Avoid logging sensitive data

## Adding Features

### New Parsers
1. Add parser function to `pkg/ingest`
2. Include format detection
3. Handle malformed input gracefully
4. Add comprehensive tests

### New Detections
1. Add detection logic to `pkg/krb`
2. Update scoring in `pkg/triage`
3. Document detection methodology
4. Include false positive considerations

### New Output Formats
1. Add writer function to `pkg/output`
2. Follow existing patterns
3. Include appropriate warnings
4. Test with various input sizes

## Security Reporting

If you discover a security vulnerability:

1. **Do NOT** create a public issue
2. Email security concerns to [security@example.com]
3. Include steps to reproduce
4. Allow time for patch before disclosure

## Legal Requirements

By contributing, you agree that:

1. Your contributions are your original work
2. You have the right to submit the work
3. You understand this tool is for authorized testing only
4. You will not add features that enable unauthorized access

## Review Process

1. **Automated Checks**: CI runs tests and linting
2. **Safety Review**: Maintainers review for safety implications
3. **Code Review**: Technical review for quality and style
4. **Testing**: Manual testing of new features

## Questions?

Feel free to open an issue for questions about contributing.
