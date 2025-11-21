# Testing Guide

This guide helps you test the spurs.gov website before and after deployment.

## Local Testing

### 1. Start Local Server

Choose one method:

**Python 3**:
```bash
python -m http.server 8000
```

**Python 2**:
```bash
python -m SimpleHTTPServer 8000
```

**Node.js**:
```bash
npx http-server -p 8000
```

**PHP**:
```bash
php -S localhost:8000
```

Visit: http://localhost:8000

### 2. Test All Pages

- [ ] Homepage (index.html)
- [ ] About page (about.html)
- [ ] Privacy policy (privacy.html)
- [ ] Accessibility statement (accessibility.html)
- [ ] 404 page (404.html)

### 3. Browser Testing

Test in multiple browsers:
- [ ] Google Chrome (latest)
- [ ] Mozilla Firefox (latest)
- [ ] Safari (latest)
- [ ] Microsoft Edge (latest)

### 4. Responsive Testing

Test at different screen sizes:
- [ ] Mobile (375px - 767px)
- [ ] Tablet (768px - 1023px)
- [ ] Desktop (1024px+)
- [ ] Large Desktop (1440px+)

## Accessibility Testing

### Keyboard Navigation

- [ ] Tab through all interactive elements
- [ ] Use Enter/Space to activate buttons/links
- [ ] Test skip link (Tab on page load)
- [ ] Verify focus indicators are visible
- [ ] Test escape key to close modals/menus

### Screen Reader Testing

**Tools**:
- Windows: NVDA (free) or JAWS
- macOS: VoiceOver (built-in)
- Linux: Orca

**Tests**:
- [ ] Navigate by headings (H key in NVDA/JAWS)
- [ ] Navigate by landmarks
- [ ] Read page content sequentially
- [ ] Verify alt text on images
- [ ] Check form labels

### Automated Tools

**WAVE (Web Accessibility Evaluation Tool)**:
1. Visit https://wave.webaim.org/
2. Enter your local URL
3. Fix any errors
4. Review warnings

**axe DevTools**:
1. Install browser extension
2. Open DevTools
3. Run axe scan
4. Fix issues

**Lighthouse**:
1. Open Chrome DevTools
2. Go to Lighthouse tab
3. Run accessibility audit
4. Aim for 100 score

## HTML/CSS Validation

### HTML Validation

1. Visit https://validator.w3.org/
2. Validate each page:
   - index.html
   - about.html
   - privacy.html
   - accessibility.html
   - 404.html
3. Fix all errors
4. Address warnings

### CSS Validation

1. Visit https://jigsaw.w3.org/css-validator/
2. Validate custom.css
3. Fix errors
4. Review warnings

## Performance Testing

### Lighthouse Performance

1. Open Chrome DevTools
2. Go to Lighthouse tab
3. Select Performance
4. Run audit
5. Target: 90+ score

**Common Issues**:
- Unoptimized images
- Render-blocking resources
- Large file sizes

### Page Load Testing

1. Use browser DevTools Network tab
2. Disable cache
3. Reload page
4. Check:
   - [ ] Total load time < 3 seconds
   - [ ] First Contentful Paint < 1.5s
   - [ ] Time to Interactive < 3.5s

## Security Testing

### Manual Checks

- [ ] HTTPS enabled (green padlock)
- [ ] Mixed content warnings (none)
- [ ] Security headers present
- [ ] No exposed secrets/keys
- [ ] Forms use HTTPS

### Security Headers

Check headers at https://securityheaders.com/

Expected headers:
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Content-Security-Policy`

### SSL/TLS Testing

1. Visit https://www.ssllabs.com/ssltest/
2. Enter spurs.gov
3. Wait for scan
4. Target: A or A+ rating

## SEO Testing

### Meta Tags

Check each page has:
- [ ] `<title>` tag (unique per page)
- [ ] Meta description
- [ ] Meta keywords
- [ ] Open Graph tags
- [ ] Viewport meta tag

### Content

- [ ] Proper heading hierarchy (h1 → h2 → h3)
- [ ] Descriptive link text (no "click here")
- [ ] Alt text on all images
- [ ] Semantic HTML elements

### Technical SEO

- [ ] robots.txt accessible
- [ ] sitemap.xml accessible
- [ ] sitemap.xml in robots.txt
- [ ] Canonical URLs set
- [ ] 404 page works

## Link Testing

### Manual

Click through all links:
- [ ] Navigation links
- [ ] Footer links
- [ ] In-content links
- [ ] External links
- [ ] Email links

### Automated

**Using link checker**:
```bash
npm install -g broken-link-checker
blc http://localhost:8000 -ro
```

## Pre-Deployment Checklist

Before pushing to production:

### Content
- [ ] All placeholder text replaced
- [ ] Contact information accurate
- [ ] Dates updated
- [ ] Spelling/grammar checked
- [ ] Images have alt text

### Technical
- [ ] HTML validates
- [ ] CSS validates
- [ ] No console errors
- [ ] All links work
- [ ] Forms work (if any)

### Accessibility
- [ ] WCAG 2.1 AA compliant
- [ ] Keyboard navigation works
- [ ] Screen reader compatible
- [ ] Color contrast sufficient

### Security
- [ ] No sensitive data exposed
- [ ] HTTPS configured
- [ ] Security headers set
- [ ] Dependencies updated

### Performance
- [ ] Images optimized
- [ ] Files minified (if applicable)
- [ ] Load time acceptable
- [ ] Mobile performance good

## Post-Deployment Testing

After deploying to production:

### Immediate (Within 1 hour)

- [ ] Site loads at https://spurs.gov
- [ ] HTTPS works (green padlock)
- [ ] WWW subdomain works
- [ ] HTTP redirects to HTTPS
- [ ] All pages accessible
- [ ] No 404 errors
- [ ] Forms work (if any)

### Within 24 Hours

- [ ] DNS fully propagated
- [ ] SSL certificate valid
- [ ] Search engines can access
- [ ] Analytics tracking (if enabled)
- [ ] Monitoring alerts working

### Within 1 Week

- [ ] Site indexed by search engines
- [ ] No broken links reported
- [ ] Performance metrics stable
- [ ] User feedback collected
- [ ] Accessibility reviewed

## Monitoring

### Tools to Set Up

1. **Google Search Console**
   - Verify ownership
   - Monitor indexing
   - Check for errors

2. **Uptime Monitoring**
   - UptimeRobot (free)
   - Pingdom
   - StatusCake

3. **Analytics** (Optional)
   - Digital Analytics Program (DAP)
   - Google Analytics (if approved)

### What to Monitor

- [ ] Uptime (99.9%+ expected)
- [ ] Page load time
- [ ] Broken links
- [ ] SSL certificate expiry
- [ ] Security vulnerabilities

## Regression Testing

After making changes:

### Quick Tests (Every Change)
- [ ] Changed pages load
- [ ] No console errors
- [ ] Links work
- [ ] Responsive design intact

### Full Tests (Monthly)
- [ ] All accessibility checks
- [ ] All performance checks
- [ ] All security checks
- [ ] Cross-browser testing

## Testing Tools Summary

### Free Tools

| Tool | Purpose | URL |
|------|---------|-----|
| HTML Validator | Validate HTML | https://validator.w3.org/ |
| CSS Validator | Validate CSS | https://jigsaw.w3.org/css-validator/ |
| WAVE | Accessibility | https://wave.webaim.org/ |
| Lighthouse | Performance, A11y, SEO | Chrome DevTools |
| SSL Labs | SSL/TLS testing | https://www.ssllabs.com/ssltest/ |
| Security Headers | Security headers | https://securityheaders.com/ |
| DNSChecker | DNS propagation | https://dnschecker.org/ |
| PageSpeed Insights | Performance | https://pagespeed.web.dev/ |

### Browser Extensions

- axe DevTools (Accessibility)
- WAVE Extension (Accessibility)
- Lighthouse (Built into Chrome)
- Web Developer Toolbar

## Automated Testing

The repository includes automated tests via GitHub Actions:

### On Every Push

- HTML/CSS validation
- Deployment to GitHub Pages

### On Pull Requests

- Accessibility testing (Pa11y)
- Link checking
- HTML validation

### Weekly

- Broken link scanning
- Security scanning (CodeQL)

## Test Data

For testing contact forms or user interactions:

**Sample Data**:
```
Name: Test User
Email: test@example.gov
Phone: (555) 123-4567
Message: This is a test message
```

**Do NOT use**:
- Real personal information
- Production data in testing
- Sensitive information

## Troubleshooting Tests

### Common Issues

**Issue**: HTML validation fails
**Solution**: Fix syntax errors, close tags properly

**Issue**: Accessibility score low
**Solution**: Add alt text, improve contrast, fix headings

**Issue**: Page load slow
**Solution**: Optimize images, remove unused CSS/JS

**Issue**: Links broken
**Solution**: Check file paths, verify external URLs

## Getting Help

If tests fail:

1. Check documentation in this repository
2. Review error messages carefully
3. Search GitHub Issues
4. Create new issue with details
5. Contact team at info@spurs.gov

## Testing Schedule

### Development
- Test locally before every commit
- Run accessibility checks weekly
- Validate HTML/CSS on changes

### Staging
- Full test suite before production
- Cross-browser testing
- Accessibility audit

### Production
- Monitor continuously
- Full audit monthly
- Security scan quarterly

---

**Remember**: Testing ensures a quality experience for all users. Take time to test thoroughly!
