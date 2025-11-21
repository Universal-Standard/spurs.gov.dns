# GitHub Pages Setup Guide for Spurs.gov

This guide provides step-by-step instructions for hosting the Spurs.gov website on GitHub Pages with custom domain configuration and verification.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Repository Setup](#repository-setup)
3. [GitHub Pages Configuration](#github-pages-configuration)
4. [Domain Verification](#domain-verification)
5. [DNS Configuration](#dns-configuration)
6. [SSL/TLS Certificate](#ssltls-certificate)
7. [Deployment](#deployment)
8. [Monitoring and Maintenance](#monitoring-and-maintenance)

## Prerequisites

Before you begin, ensure you have:

- [ ] Administrative access to this GitHub repository
- [ ] Control over the spurs.gov domain DNS settings
- [ ] Organization owner/admin permissions (for domain verification)
- [ ] Understanding of DNS management

## Repository Setup

### 1. Repository Structure

The repository should have the following structure:

```
spurs.gov.dns/
├── index.html              # Main homepage
├── CNAME                   # Custom domain configuration
├── 404.html               # Custom 404 page
├── robots.txt             # Search engine directives
├── sitemap.xml            # Site structure for search engines
├── privacy.html           # Privacy policy
├── accessibility.html     # Accessibility statement
├── assets/
│   ├── css/
│   │   └── custom.css
│   ├── js/
│   └── images/
├── .well-known/
│   └── security.txt       # Security vulnerability disclosure
└── .github/
    └── workflows/
        ├── deploy.yml           # GitHub Pages deployment
        ├── accessibility.yml    # Accessibility testing
        └── link-checker.yml     # Link validation
```

### 2. CNAME File

The `CNAME` file contains your custom domain:

```
spurs.gov
```

This tells GitHub Pages to serve the site at `spurs.gov` instead of `username.github.io`.

## GitHub Pages Configuration

### Enable GitHub Pages

1. Go to your repository on GitHub
2. Click **Settings** → **Pages**
3. Under **Source**, select the branch to deploy (usually `main` or `master`)
4. Click **Save**

### Branch Configuration

The deployment workflow (`.github/workflows/deploy.yml`) automatically deploys when you push to the main branch.

## Domain Verification

Domain verification is **critical** for .gov websites to prevent domain takeovers.

### Step 1: Get Verification Code

1. Go to your **Organization Settings** (not repository settings)
2. Navigate to **Verified & approved domains**
3. Click **Add a domain**
4. Enter `spurs.gov`
5. GitHub will provide a TXT record code like: `_github-challenge-ORGNAME-DOMAIN.spurs.gov`

### Step 2: Add DNS TXT Record

Add the verification TXT record to your DNS:

```
Type: TXT
Host: _github-challenge-ORGNAME-DOMAIN
Value: [code provided by GitHub]
TTL: 3600 (or default)
```

### Step 3: Verify Domain

1. Wait for DNS propagation (may take up to 72 hours, usually much faster)
2. Return to GitHub Organization Settings
3. Click **Verify** next to your domain
4. Once verified, the domain is protected from takeover

### Why Domain Verification Matters

- Prevents malicious actors from claiming your domain on GitHub
- Protects all subdomains (e.g., `www.spurs.gov`, `blog.spurs.gov`)
- Required best practice for government websites
- Ensures only your organization can publish to your domain

## DNS Configuration

Configure your DNS to point to GitHub Pages:

### Option 1: Apex Domain (spurs.gov)

Add **A records** pointing to GitHub Pages IP addresses:

```
Type: A
Host: @
Value: 185.199.108.153
TTL: 3600

Type: A
Host: @
Value: 185.199.109.153
TTL: 3600

Type: A
Host: @
Value: 185.199.110.153
TTL: 3600

Type: A
Host: @
Value: 185.199.111.153
TTL: 3600
```

### Option 2: WWW Subdomain (www.spurs.gov)

Add a **CNAME record**:

```
Type: CNAME
Host: www
Value: [your-org].github.io
TTL: 3600
```

### Option 3: Both Apex and WWW

Use Option 1 for apex domain, and add:

```
Type: CNAME
Host: www
Value: spurs.gov
TTL: 3600
```

### Additional DNS Records for .gov Sites

> **Note**: See [DNS_MANAGEMENT.md](DNS_MANAGEMENT.md) for comprehensive DNS best practices following GSA-TTS patterns.

#### DNSSEC (Recommended)

Enable DNSSEC through your DNS provider for added security. DNSSEC is strongly recommended for all .gov domains by CISA.

#### CAA Records (Recommended)

Restrict which Certificate Authorities can issue certificates:

```
Type: CAA
Host: @
Value: 0 issue "letsencrypt.org"
TTL: 3600

Type: CAA
Host: @
Value: 0 issue "pki.goog"
TTL: 3600
```

## SSL/TLS Certificate

GitHub Pages automatically provides free SSL certificates via Let's Encrypt.

### Enable HTTPS

1. Go to **Settings** → **Pages**
2. Check **Enforce HTTPS**
3. Wait for certificate provisioning (up to 24 hours)

### Verify HTTPS

Once enabled, your site will be accessible at:
- `https://spurs.gov` ✅
- `http://spurs.gov` → redirects to HTTPS ✅

## Deployment

### Automatic Deployment

The workflow in `.github/workflows/deploy.yml` automatically:

1. Validates HTML/CSS
2. Builds the site
3. Deploys to GitHub Pages
4. Updates the live site

### Manual Deployment

To manually trigger deployment:

1. Go to **Actions** tab
2. Select **Deploy to GitHub Pages** workflow
3. Click **Run workflow**

### Deployment Status

Check deployment status:
- **Actions** tab shows workflow runs
- **Environments** shows deployment history
- **Settings → Pages** shows current status

## Monitoring and Maintenance

### Automated Checks

The repository includes automated workflows for:

- **HTML/CSS Validation**: Runs on every push
- **Accessibility Testing**: Tests WCAG 2.1 AA compliance
- **Link Checking**: Weekly scan for broken links
- **CodeQL Security**: Scans for vulnerabilities

### Manual Checks

Regularly verify:

- [ ] Site loads correctly at https://spurs.gov
- [ ] SSL certificate is valid and not expiring
- [ ] DNS records are correct
- [ ] All pages are accessible
- [ ] Forms and interactive elements work
- [ ] Mobile responsiveness
- [ ] Browser compatibility

### Analytics

This site uses the Digital Analytics Program (DAP):

- Government-wide analytics for federal websites
- No PII collection
- Provides aggregate usage statistics
- Configure in HTML: Update `agency=AGENCY` parameter

### Updates and Changes

To update the website:

1. Create a new branch: `git checkout -b feature/update-name`
2. Make your changes
3. Test locally
4. Commit and push
5. Create a pull request
6. After review and approval, merge to main
7. Site automatically deploys

## Troubleshooting

### Site Not Loading

1. Check DNS propagation: `dig spurs.gov`
2. Verify CNAME file contains correct domain
3. Check GitHub Pages settings
4. Wait for DNS propagation (up to 72 hours)

### SSL Certificate Issues

1. Ensure HTTPS enforcement is enabled
2. Wait 24 hours for certificate provisioning
3. Check CAA records don't block Let's Encrypt
4. Verify DNS is correctly configured

### Domain Verification Failed

1. Check TXT record is correctly added
2. Wait for DNS propagation: `dig TXT _github-challenge-ORGNAME.spurs.gov`
3. Ensure you're verifying from Organization Settings, not repo settings
4. Contact GitHub Support if issues persist

### 404 Errors

1. Check file paths are correct
2. Ensure files are committed and pushed
3. Verify deployment completed successfully
4. Check .gitignore isn't excluding files

## Best Practices

### Security

- ✅ Enable HTTPS enforcement
- ✅ Add security.txt for vulnerability disclosure
- ✅ Implement security headers
- ✅ Regular security scans
- ✅ Keep dependencies updated

### Accessibility

- ✅ WCAG 2.1 AA compliance
- ✅ Keyboard navigation support
- ✅ Screen reader compatibility
- ✅ Regular accessibility testing
- ✅ Alternative text for images

### Performance

- ✅ Optimize images
- ✅ Minimize CSS/JS
- ✅ Use CDN for libraries (USWDS)
- ✅ Enable browser caching
- ✅ Monitor page load times

### SEO

- ✅ Descriptive meta tags
- ✅ Semantic HTML
- ✅ Updated sitemap.xml
- ✅ Proper robots.txt
- ✅ Schema.org markup (recommended)

## Additional Resources

### GitHub Documentation

- [GitHub Pages Documentation](https://docs.github.com/en/pages)
- [Custom Domains for GitHub Pages](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site)
- [Verifying Custom Domain](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages)

### Government Resources

- [Digital.gov](https://digital.gov/)
- [U.S. Web Design System](https://designsystem.digital.gov/)
- [Section 508](https://www.section508.gov/)
- [Cloud.gov Pages](https://cloud.gov/pages/)
- [GSA-TTS DNS Architecture](https://github.com/gsa-tts/dns) - Infrastructure as Code patterns
- [CISA DNSSEC Guidance](https://www.cisa.gov/dnssec)

### Tools

- [HTML Validator](https://validator.w3.org/)
- [CSS Validator](https://jigsaw.w3.org/css-validator/)
- [WAVE Accessibility Tool](https://wave.webaim.org/)
- [DNS Checker](https://dnschecker.org/)

## Alternative: Infrastructure as Code

For organizations wanting Terraform-managed DNS (following GSA-TTS patterns):

- See [terraform/README.md](terraform/README.md) for optional Terraform configuration
- Example configuration: [terraform/examples/github-pages.tf](terraform/examples/github-pages.tf)
- Provides Git-based change tracking and peer review for DNS changes
- Trade-off: Adds ~$0.50/month cost for Route 53 hosted zone

**Note**: This is optional. Direct DNS management (documented above) is simpler and free.

## Support

For assistance:

- **Technical Issues**: Create a GitHub Issue
- **Security Concerns**: security@spurs.gov
- **General Questions**: info@spurs.gov
- **DNS Questions**: See [DNS_MANAGEMENT.md](DNS_MANAGEMENT.md)

---

**Last Updated**: November 12, 2025
