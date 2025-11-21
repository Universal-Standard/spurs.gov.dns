# Contributing to Spurs.gov

Thank you for your interest in contributing to Spurs.gov! This document provides guidelines for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@spurs.gov.

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug Reports**: Report bugs via GitHub Issues
- **Feature Requests**: Suggest new features or enhancements
- **Documentation**: Improve or correct documentation
- **Code**: Submit code changes via Pull Requests
- **Accessibility**: Help improve accessibility compliance
- **Testing**: Report testing results and coverage improvements

### Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your contribution
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Setup

### Prerequisites

- Git
- Modern web browser
- Text editor or IDE
- (Optional) Local web server for testing

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/Universal-Standard/spurs.gov.dns.git
   cd spurs.gov.dns
   ```

2. Start a local web server:
   ```bash
   # Using Python
   python -m http.server 8000
   
   # Using Node.js
   npx http-server -p 8000
   
   # Using PHP
   php -S localhost:8000
   ```

3. Open your browser to `http://localhost:8000`

### Testing

Before submitting changes, ensure:

- HTML validates (https://validator.w3.org/)
- CSS validates (https://jigsaw.w3.org/css-validator/)
- Links are functional
- Accessibility standards are met (WCAG 2.1 AA)
- Site works on multiple browsers
- Site is mobile-responsive

## Submitting Changes

### Pull Request Process

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write clear, concise commit messages
   - Follow the style guidelines
   - Update documentation as needed
   - Add tests if applicable

3. **Test Your Changes**
   - Validate HTML/CSS
   - Check accessibility
   - Test across browsers
   - Verify mobile responsiveness

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Clear description of changes"
   ```

5. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit Pull Request**
   - Provide a clear title and description
   - Reference any related issues
   - Include screenshots for UI changes
   - List any breaking changes

### Pull Request Guidelines

- Keep changes focused and atomic
- Update relevant documentation
- Ensure all tests pass
- Follow coding standards
- Be responsive to feedback
- Be patient during review process

## Style Guidelines

### HTML

- Use semantic HTML5 elements
- Include proper ARIA labels
- Ensure proper heading hierarchy
- Use descriptive alt text for images
- Follow WCAG 2.1 AA guidelines

### CSS

- Use the U.S. Web Design System (USWDS) utilities when possible
- Follow BEM naming convention for custom classes
- Ensure sufficient color contrast
- Support responsive design
- Test with different zoom levels

### JavaScript

- Use modern ES6+ syntax
- Include comments for complex logic
- Ensure accessibility of interactive elements
- Test with keyboard navigation
- Handle errors gracefully

### Accessibility

- Support keyboard navigation
- Include skip links
- Provide text alternatives
- Ensure color contrast
- Test with screen readers
- Support zoom up to 200%

### Git Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and PRs when relevant

Example:
```
Add accessibility improvements to navigation

- Add skip link for keyboard users
- Improve ARIA labels on menu items
- Ensure focus indicators are visible

Fixes #123
```

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- Clear and descriptive title
- Steps to reproduce
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Browser and OS information
- Any error messages

### Feature Requests

When requesting features:

- Provide clear use case
- Explain benefits
- Consider alternatives
- Check for existing requests

## Security Vulnerabilities

**Do not report security vulnerabilities through GitHub Issues.**

Instead, report them via:
- Email: security@spurs.gov
- See [SECURITY.md](SECURITY.md) for details

## Licensing

By contributing to this project, you agree that your contributions will be licensed under the same license as the project.

## Recognition

Contributors will be acknowledged in our documentation. Thank you for helping improve Spurs.gov!

## Questions?

If you have questions about contributing:

- Email: info@spurs.gov
- Create a GitHub Discussion
- Review existing documentation

## Additional Resources

- [U.S. Web Design System](https://designsystem.digital.gov/)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [Section 508 Standards](https://www.section508.gov/)
- [GitHub Flow Guide](https://guides.github.com/introduction/flow/)

---

**Last Updated**: November 12, 2025

Thank you for contributing to Spurs.gov!
