# Quick Start Guide - Spurs.gov on GitHub Pages

Get your .gov website live on GitHub Pages in under 30 minutes!

## ⚡ Quick Start (5 Steps)

### Step 1: Enable GitHub Pages (2 minutes)

1. Go to repository **Settings** → **Pages**
2. Under **Source**, select branch: `main` (or `master`)
3. Click **Save**
4. Note the temporary URL: `https://[org-name].github.io/spurs.gov.dns`

### Step 2: Verify Domain Ownership (10 minutes)

**Critical for .gov security!**

1. Go to **Organization Settings** (not repository settings)
2. Click **Verified & approved domains**
3. Click **Add a domain** → Enter `spurs.gov`
4. GitHub provides a TXT record like:
   ```
   _github-challenge-ORGNAME-DOMAIN.spurs.gov
   ```
5. Add this TXT record to your DNS
6. Wait 5-10 minutes for DNS propagation
7. Click **Verify** in GitHub

✅ **Your domain is now protected from takeover!**

### Step 3: Configure DNS (5 minutes)

Add these DNS records (replace existing if necessary):

```dns
# A Records for Apex Domain
Type: A    Host: @    Value: 185.199.108.153   TTL: 3600
Type: A    Host: @    Value: 185.199.109.153   TTL: 3600
Type: A    Host: @    Value: 185.199.110.153   TTL: 3600
Type: A    Host: @    Value: 185.199.111.153   TTL: 3600

# CNAME for WWW
Type: CNAME    Host: www    Value: spurs.gov    TTL: 3600
```

**DNS Propagation**: May take up to 72 hours (usually much faster)

### Step 4: Enable HTTPS (5 minutes)

1. Go to **Settings** → **Pages**
2. Wait for "DNS check successful" message
3. Check **Enforce HTTPS**
4. Wait up to 24 hours for SSL certificate (usually instant)

### Step 5: Verify Everything Works (5 minutes)

Visit your site:
- ✅ https://spurs.gov (should load)
- ✅ https://www.spurs.gov (should load)
- ✅ http://spurs.gov → redirects to HTTPS
- ✅ Green padlock in browser
- ✅ No certificate warnings

## 🎉 You're Live!

Your .gov website is now:
- ✅ Hosted on GitHub Pages (free!)
- ✅ Secured with HTTPS
- ✅ Protected from domain takeover
- ✅ Automatically deployed on every push

## 🔧 What's Included

Your site now has:

### Core Pages
- **Homepage** (`index.html`) - Modern, accessible design
- **About Page** (`about.html`) - Organization information
- **Privacy Policy** (`privacy.html`) - Required for government sites
- **Accessibility Statement** (`accessibility.html`) - Section 508 compliance
- **Custom 404 Page** (`404.html`) - User-friendly error page

### Security Features
- HTTPS enforcement
- Security headers (CSP, HSTS, X-Frame-Options)
- Security.txt for vulnerability disclosure
- Domain verification protection
- CodeQL security scanning

### Compliance Features
- WCAG 2.1 AA accessibility
- Section 508 compliance
- U.S. Web Design System (USWDS)
- Digital Analytics Program (DAP) integration
- Government banner

### Automation
- Auto-deploy on push to main branch
- HTML/CSS validation
- Accessibility testing (Pa11y)
- Weekly link checking
- Security scanning

## 📝 Next Steps

### Customize Your Site

1. **Update Content**: Edit HTML files with your actual content
2. **Add Logo**: Place `favicon.png` in `assets/images/`
3. **Add Images**: Upload to `assets/images/`
4. **Customize Styles**: Edit `assets/css/custom.css`
5. **Update Contact Info**: Search for `info@spurs.gov` and update

### Add Team Members

1. Go to repository **Settings** → **Collaborators**
2. Add team members with appropriate permissions:
   - **Admin**: Full control (federal employees only)
   - **Write**: Can push code
   - **Read**: View only

### Set Up Branches Protection

1. Go to **Settings** → **Branches**
2. Add rule for `main` branch:
   - ✅ Require pull request reviews
   - ✅ Require status checks to pass
   - ✅ Include administrators

## 🔄 Making Updates

### Method 1: GitHub Web Editor (Easy)

1. Navigate to file on GitHub
2. Click pencil icon (Edit)
3. Make changes
4. Commit directly or create pull request
5. Site auto-deploys in ~2 minutes

### Method 2: Local Development (Recommended)

```bash
# Clone repository
git clone https://github.com/Universal-Standard/spurs.gov.dns.git
cd spurs.gov.dns

# Make changes
# Edit HTML/CSS files

# Test locally
python -m http.server 8000
# Visit http://localhost:8000

# Commit and push
git add .
git commit -m "Description of changes"
git push origin main

# Site auto-deploys
```

## 🆘 Troubleshooting

### Site Not Loading

**Problem**: Visiting spurs.gov shows error or old site

**Solutions**:
1. Check DNS propagation: Visit https://dnschecker.org
2. Clear browser cache (Ctrl+Shift+Delete)
3. Wait up to 72 hours for DNS to fully propagate
4. Verify A records point to GitHub Pages IPs

### HTTPS Not Working

**Problem**: Site shows "Not Secure" or certificate warning

**Solutions**:
1. Wait 24 hours for certificate provisioning
2. Ensure "Enforce HTTPS" is checked
3. Check DNS is correctly configured
4. Verify no CAA records block Let's Encrypt

### Domain Verification Failed

**Problem**: GitHub can't verify domain ownership

**Solutions**:
1. Verify TXT record is added correctly
2. Check from Organization Settings (not repo)
3. Wait 10-30 minutes for DNS propagation
4. Use `dig TXT _github-challenge-ORGNAME.spurs.gov` to verify

### Deployment Failed

**Problem**: GitHub Actions shows red X

**Solutions**:
1. Check **Actions** tab for error details
2. Fix HTML validation errors
3. Ensure all files are committed
4. Check workflow permissions

## 📚 Additional Resources

- **Full Setup Guide**: [GITHUB_PAGES_SETUP.md](GITHUB_PAGES_SETUP.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security**: [SECURITY.md](SECURITY.md)
- **GitHub Docs**: https://docs.github.com/en/pages

## 💰 Cost Comparison

| Option | Monthly Cost | Setup Time | Maintenance |
|--------|--------------|------------|-------------|
| **GitHub Pages** | $0 | 30 minutes | Minimal |
| AWS EC2 (t2.micro) | ~$10 | 2-3 hours | High |
| AWS EC2 (t2.small) | ~$20 | 2-3 hours | High |

**Annual Savings with GitHub Pages**: $120-$240+

## 🔐 Security Checklist

Before going live, verify:

- [ ] Domain verification completed
- [ ] HTTPS enforcement enabled
- [ ] Security.txt configured
- [ ] Security headers implemented
- [ ] CodeQL scanning enabled
- [ ] Branch protection enabled
- [ ] Team permissions configured
- [ ] Contact emails updated
- [ ] Analytics configured (if needed)

## ✨ Pro Tips

1. **Always work in branches**: Never commit directly to main
2. **Use pull requests**: Get peer review for changes
3. **Test locally first**: Catch errors before deployment
4. **Monitor Actions**: Watch deployment workflows
5. **Keep it simple**: Static HTML is fast and secure
6. **Update regularly**: Keep dependencies current
7. **Document changes**: Good commit messages help everyone

## 🎓 Learning Resources

New to GitHub Pages? Start here:
- [GitHub Skills](https://skills.github.com/)
- [GitHub Pages Tutorial](https://pages.github.com/)
- [USWDS Getting Started](https://designsystem.digital.gov/documentation/getting-started/)

## 📞 Support

Need help?
- **Documentation**: Check the guides in this repository
- **Issues**: Create a GitHub Issue
- **Security**: security@spurs.gov
- **General**: info@spurs.gov

---

**Congratulations! Your .gov website is live on GitHub Pages!** 🎉

For detailed instructions, see [GITHUB_PAGES_SETUP.md](GITHUB_PAGES_SETUP.md)
