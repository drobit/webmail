# Contributing to Rust Webmail Client

Thank you for your interest in contributing to our high-performance Rust webmail client! 🎉

We welcome contributions from developers of all skill levels. This guide will help you get started with contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Community](#community)

## 🤝 Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow:

- **Be respectful** and inclusive
- **Be constructive** in discussions and feedback
- **Focus on the code**, not the person
- **Help others** learn and grow
- **Respect different perspectives** and experiences

## 🚀 Getting Started

### Prerequisites

Before contributing, make sure you have:

- **Rust 1.70+** installed ([Install Rust](https://rustup.rs/))
- **PostgreSQL 12+** running locally
- **Git** for version control
- **Basic knowledge** of Rust, async programming, and web development

### Development Setup

1. **Fork and clone** the repository:
```bash
git clone https://github.com/drobit/webmail.git
cd webmail
```

2. **Set up the development environment**:
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your credentials
# See README.md for detailed setup instructions
```

3. **Install development tools**:
```bash
# Auto-rebuild on file changes
cargo install cargo-watch

# Code formatting
rustup component add rustfmt

# Linting
rustup component add clippy

# WebAssembly tools (for frontend)
cargo install wasm-pack
```

4. **Set up the database**:
```bash
createdb webmail_db
psql webmail_db < database_schema.sql
```

5. **Run the development server**:
```bash
# Auto-rebuild and restart on changes
cargo watch -x run

# Or run normally
cargo run
```

## 🛠️ How to Contribute

### Types of Contributions

We welcome various types of contributions:

#### 🐛 Bug Fixes
- Fix existing issues
- Improve error handling
- Resolve performance bottlenecks

#### ⚡ Performance Improvements
- Optimize IMAP operations
- Improve database queries
- Enhance frontend responsiveness

#### ✨ New Features
- Email filtering and search
- Multiple account support
- Advanced compose features
- Mobile app integration

#### 📚 Documentation
- Improve README and guides
- Add code comments
- Create tutorials and examples

#### 🧪 Testing
- Add unit tests
- Create integration tests
- Improve test coverage

#### 🎨 UI/UX Improvements
- Enhance responsive design
- Improve accessibility
- Add dark mode
- Modernize styling

### Getting Assigned to Issues

1. **Browse open issues** in the [Issues tab](https://github.com/drobit/webmail/issues)
2. **Comment on an issue** you'd like to work on
3. **Wait for assignment** from maintainers
4. **Start working** once assigned

For new contributors, look for issues labeled:
- `good first issue`
- `help wanted`
- `documentation`

## 📝 Coding Standards

### Rust Code Style

Follow standard Rust conventions:

```bash
# Format your code before committing
cargo fmt

# Check for common mistakes
cargo clippy

# Run all checks
cargo fmt && cargo clippy && cargo test
```

### Code Quality Guidelines

1. **Write clear, readable code**:
```rust
// Good: Clear function name and documentation
/// Extracts readable text content from email body
fn extract_plain_text(body: &str) -> String {
    // Implementation...
}

// Avoid: Unclear naming
fn process(data: &str) -> String {
    // Implementation...
}
```

2. **Handle errors properly**:
```rust
// Good: Proper error handling
match fetch_emails().await {
    Ok(emails) => process_emails(emails),
    Err(e) => {
        eprintln!("Failed to fetch emails: {}", e);
        return Err(e);
    }
}

// Avoid: Unwrapping without context
let emails = fetch_emails().await.unwrap();
```

3. **Write meaningful comments**:
```rust
// Good: Explains why, not what
// Use UID-based lookup for faster email access
let email = get_email_by_uid(uid).await?;

// Avoid: Obvious comments
// Get email by UID
let email = get_email_by_uid(uid).await?;
```

4. **Use appropriate data structures**:
```rust
// Good: Use Vec for ordered collections
let mut emails: Vec<EmailDetail> = Vec::new();

// Good: Use HashMap for key-value lookups
let mut cache: HashMap<String, EmailDetail> = HashMap::new();
```

### Frontend Guidelines

1. **Use modern JavaScript** (ES6+)
2. **Follow existing patterns** in the codebase
3. **Write semantic HTML** with proper accessibility
4. **Use CSS classes** instead of inline styles
5. **Handle errors gracefully** with user-friendly messages

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_email_validation

# Run tests in specific module
cargo test lib::tests
```

### Writing Tests

1. **Unit tests** for individual functions:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email_format() {
        assert!(validate_email_format("test@example.com"));
        assert!(!validate_email_format("invalid-email"));
    }
}
```

2. **Integration tests** for API endpoints:
```rust
#[actix_web::test]
async fn test_fetch_emails() {
    let app = test::init_service(create_app()).await;
    let req = test::TestRequest::get()
        .uri("/emails?limit=10")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
```

3. **Property-based tests** for complex logic:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_email_truncation(s in "\\PC*", max_len in 1usize..100) {
        let result = truncate_subject(&s, max_len);
        assert!(result.len() <= max_len);
    }
}
```

### Test Requirements

- **All new features** must include tests
- **Bug fixes** should include regression tests
- **Aim for 80%+ code coverage** on new code
- **Tests should be fast** and reliable

## 🔄 Pull Request Process

### Before Submitting

1. **Create a feature branch**:
```bash
git checkout -b feature/email-search
# or
git checkout -b bugfix/imap-connection-issue
```

2. **Make your changes** following coding standards

3. **Add/update tests** as needed

4. **Run the full test suite**:
```bash
cargo fmt
cargo clippy
cargo test
```

5. **Update documentation** if needed

6. **Commit with clear messages**:
```bash
git commit -m "feat: add email search functionality

- Add search endpoint with query parameter support
- Implement database search with full-text indexing
- Add frontend search UI with debounced input
- Include tests for search functionality

Closes #123"
```

### Commit Message Format

Use conventional commits:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for formatting changes
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance tasks

### Pull Request Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] Tests pass locally
- [ ] Added new tests for changes
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)

## Screenshots/Demo
(If applicable)

## Related Issues
Closes #issue_number
```

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **At least one maintainer** reviews the code
3. **Address feedback** from reviewers
4. **Squash commits** if requested
5. **Merge** after approval

## 🐛 Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Bug Description**
Clear description of the bug

**Steps to Reproduce**
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: [e.g., Windows 10, macOS 12, Ubuntu 20.04]
- Rust version: [e.g., 1.70.0]
- Browser: [e.g., Chrome 91, Firefox 89]

**Additional Context**
Logs, screenshots, etc.
```

### Feature Requests

Use the feature request template:

```markdown
**Feature Description**
Clear description of the feature

**Use Case**
Why is this feature needed?

**Proposed Solution**
How should this be implemented?

**Alternatives Considered**
Other approaches you've thought about

**Additional Context**
Any other context or screenshots
```

### Security Issues

For security vulnerabilities:

1. **Do NOT create a public issue**
2. **Email maintainers directly**: security@yourproject.com
3. **Include detailed information** about the vulnerability
4. **Wait for response** before public disclosure

## 💬 Community

### Communication Channels

- **GitHub Discussions**: For questions and general discussion
- **GitHub Issues**: For bug reports and feature requests
- **Email**: For security issues and private matters

### Getting Help

If you need help:

1. **Check existing issues** and documentation
2. **Search GitHub Discussions**
3. **Create a new discussion** with the "help wanted" label
4. **Join community discussions** and help others

### Recognition

Contributors are recognized through:

- **GitHub contributor graph**
- **Release notes** mentions
- **Hall of fame** in documentation
- **Special badges** for significant contributions

## 📊 Project Metrics

We track various metrics to ensure project health:

- **Code coverage**: Aim for 80%+
- **Performance**: Email fetch time < 2 seconds
- **Reliability**: 99%+ uptime in production
- **Security**: Regular dependency updates

## 🎯 Roadmap

Current priorities (see [Issues](https://github.com/frobit/webmail/issues) for details):

### Short-term (1-3 months)
- [ ] Email search functionality
- [ ] Dark mode support
- [ ] Mobile app improvements
- [ ] Performance optimizations

### Medium-term (3-6 months)
- [ ] Multiple account support
- [ ] Advanced filtering
- [ ] Keyboard shortcuts
- [ ] Offline support

### Long-term (6+ months)
- [ ] Plugin system
- [ ] Calendar integration
- [ ] Advanced security features
- [ ] Machine learning features

## 🙏 Thank You

Thank you for contributing to making this webmail client better for everyone! Every contribution, no matter how small, makes a difference.

Happy coding! 🚀

---

**Questions?** Feel free to reach out via [GitHub Discussions](https://github.com/drobit/webmail/discussions) or create an issue.