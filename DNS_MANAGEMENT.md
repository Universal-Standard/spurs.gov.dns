# DNS Management for Spurs.gov

This document describes DNS management practices for spurs.gov, following patterns established by GSA-TTS for .gov domains.

## Overview

DNS for spurs.gov can be managed through two approaches:

1. **GitHub Pages DNS** (Current Implementation) - Simplified DNS pointing directly to GitHub Pages
2. **Infrastructure as Code** (Optional) - Terraform-managed DNS via AWS Route 53

## Current Architecture: GitHub Pages DNS

### DNS Records

The current implementation uses direct DNS A records pointing to GitHub Pages:

```dns
# Primary domain A records (GitHub Pages IPs)
Type: A     Host: @     Value: 185.199.108.153   TTL: 3600
Type: A     Host: @     Value: 185.199.109.153   TTL: 3600
Type: A     Host: @     Value: 185.199.110.153   TTL: 3600
Type: A     Host: @     Value: 185.199.111.153   TTL: 3600

# WWW subdomain
Type: CNAME Host: www   Value: spurs.gov         TTL: 3600

# Domain verification (prevents takeover)
Type: TXT   Host: _github-challenge-ORGNAME-DOMAIN   Value: [GitHub verification code]

# DNSSEC (highly recommended for .gov domains)
Type: DS    Host: @     Value: [DS record from DNS provider]
```

### Why Direct DNS?

Following GSA-TTS patterns but adapted for GitHub Pages:
- **Simplicity**: No intermediate DNS service needed
- **Cost**: $0 compared to Route 53 hosted zone fees
- **Performance**: Direct resolution, no additional hops
- **Security**: GitHub's global CDN with DDoS protection

## Best Practices from GSA-TTS

### 1. DNSSEC (Domain Name System Security Extensions)

**Status**: ⚠️ Recommended but requires DNS provider support

DNSSEC adds cryptographic signatures to DNS records to prevent cache poisoning and DNS spoofing attacks.

**Implementation**:
1. Enable DNSSEC at your DNS registrar/provider
2. Obtain DS (Delegation Signer) records
3. Add DS records to parent zone (.gov registry)

**For .gov domains**, DNSSEC is strongly recommended by CISA.

### 2. Low TTL During Changes

Following GSA-TTS practice:
- **Before changes**: Lower TTL to 300 seconds (5 minutes)
- **During testing**: Keep TTL low to facilitate rollback
- **After verification**: Increase TTL to 3600 seconds (1 hour)

**Why**: Allows quick DNS changes and rollback if issues occur.

### 3. DNS Record Validation

**Automated validation** (included in our workflows):
```yaml
# .github/workflows/dns-validation.yml
- name: Validate DNS Configuration
  run: |
    # Check A records point to GitHub Pages
    # Verify CNAME is correct
    # Confirm domain verification TXT record
```

### 4. Change Management Process

Following GSA-TTS model:

1. **Pull Request Required**: All DNS changes via PR
2. **Peer Review**: At least one reviewer approval
3. **Testing**: Verify changes before production
4. **Documentation**: Update this file with changes
5. **Monitoring**: Watch for issues post-deployment

### 5. Nameserver Documentation

**Current nameservers** (for spurs.gov):
- Managed by: [DNS Provider Name]
- Verification: Check with `dig spurs.gov NS`

```bash
# Verify current nameservers
dig spurs.gov NS +short
```

Expected output should show your DNS provider's nameservers.

## Alternative: Infrastructure as Code (Optional)

For organizations wanting Terraform-managed DNS similar to GSA-TTS:

### Terraform DNS Configuration

If migrating to AWS Route 53 + Terraform:

```hcl
# terraform/spurs.gov.tf

# Create hosted zone
resource "aws_route53_zone" "spurs_gov_zone" {
  name = "spurs.gov"
  
  tags = {
    Project     = "spurs.gov"
    ManagedBy   = "Terraform"
    Environment = "production"
  }
}

# A records for GitHub Pages (if keeping GitHub Pages hosting)
resource "aws_route53_record" "spurs_gov_github_pages_a" {
  count   = 4
  zone_id = aws_route53_zone.spurs_gov_zone.zone_id
  name    = "spurs.gov"
  type    = "A"
  ttl     = 3600
  
  records = [
    "185.199.108.153",
    "185.199.109.153", 
    "185.199.110.153",
    "185.199.111.153"
  ][count.index]
}

# CNAME for www
resource "aws_route53_record" "spurs_gov_www_cname" {
  zone_id = aws_route53_zone.spurs_gov_zone.zone_id
  name    = "www.spurs.gov"
  type    = "CNAME"
  ttl     = 3600
  records = ["spurs.gov"]
}

# Domain verification
resource "aws_route53_record" "spurs_gov_github_verification" {
  zone_id = aws_route53_zone.spurs_gov_zone.zone_id
  name    = "_github-challenge-ORGNAME-DOMAIN.spurs.gov"
  type    = "TXT"
  ttl     = 300
  records = ["${var.github_verification_code}"]
}

# Enable DNSSEC
module "spurs_gov_dnssec" {
  source = "./dnssec"
  zone   = aws_route53_zone.spurs_gov_zone
}

# Output nameservers for domain registrar
output "spurs_gov_ns" {
  description = "Nameservers to configure at .gov registrar"
  value       = aws_route53_zone.spurs_gov_zone.name_servers
}

# Output DS record for DNSSEC
output "spurs_gov_ds" {
  description = "DS record to add to .gov registry for DNSSEC"
  value       = module.spurs_gov_dnssec.ds_record
}
```

### Benefits of Terraform Approach

- **Version Control**: All DNS changes tracked in Git
- **Peer Review**: Required before changes go live
- **Automation**: CI/CD pipeline validates and deploys
- **Rollback**: Easy to revert to previous state
- **Consistency**: Standardized across multiple domains

### Trade-offs

| Aspect | Direct DNS (Current) | Terraform + Route 53 |
|--------|---------------------|---------------------|
| Cost | $0 | ~$0.50/month per zone |
| Setup Time | 5 minutes | 1-2 hours |
| Maintenance | Minimal | Requires Terraform knowledge |
| Flexibility | Limited | High |
| Best For | Simple setups | Multiple domains/complex DNS |

## Monitoring

### DNS Health Checks

**Automated checks** (can be added):

```yaml
# .github/workflows/dns-monitor.yml
name: DNS Health Check

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  dns-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check A Records
        run: |
          dig spurs.gov A +short | grep -E '^185\.199\.(108|109|110|111)\.153$'
      
      - name: Check HTTPS
        run: |
          curl -I https://spurs.gov | grep "HTTP/2 200"
      
      - name: Check Domain Verification
        run: |
          dig _github-challenge-ORGNAME-DOMAIN.spurs.gov TXT +short
```

### What to Monitor

1. **DNS Resolution**: A records resolve correctly
2. **HTTPS Status**: SSL certificate valid
3. **Page Availability**: Site loads successfully
4. **DNSSEC Status**: DNSSEC validation passes

## Emergency Procedures

### DNS Propagation Issues

If DNS changes aren't propagating:

1. **Check TTL**: Wait for TTL period to expire
2. **Verify Records**: Use `dig` to check authoritative servers
3. **Clear Cache**: Flush local DNS cache
4. **Rollback**: Revert to previous DNS configuration

### Site Unreachable

1. **Check GitHub Status**: https://www.githubstatus.com/
2. **Verify DNS**: Ensure A records are correct
3. **Check CNAME file**: Must contain only `spurs.gov`
4. **Review Workflows**: Check GitHub Actions for failures

## DNS Security

### Best Practices

1. ✅ **Enable DNSSEC**: Protects against DNS spoofing
2. ✅ **Domain Verification**: Prevents GitHub Pages takeover
3. ✅ **CAA Records**: Restrict certificate issuance
4. ✅ **Monitor Changes**: Alert on unexpected DNS changes
5. ✅ **Document Everything**: Keep this file updated

### CAA Records (Certificate Authority Authorization)

Restrict which CAs can issue certificates:

```dns
# Allow only Let's Encrypt (used by GitHub Pages)
Type: CAA  Host: @  Value: 0 issue "letsencrypt.org"
Type: CAA  Host: @  Value: 0 issue "pki.goog"

# Incident reporting
Type: CAA  Host: @  Value: 0 iodef "mailto:security@spurs.gov"
```

## Change Log

All DNS changes should be documented here:

| Date | Change | Made By | PR # |
|------|--------|---------|------|
| 2025-11-12 | Initial GitHub Pages DNS setup | Copilot | #XX |

## Resources

### Official Documentation

- [GitHub Pages Custom Domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site)
- [GitHub Domain Verification](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages)
- [CISA DNSSEC Guidance](https://www.cisa.gov/dnssec)
- [.gov Domain Management](https://home.dotgov.gov/)

### GSA-TTS References

- [GSA-TTS DNS Repository](https://github.com/gsa-tts/dns)
- [GSA-TTS DNS Architecture](https://github.com/gsa-tts/dns/blob/main/doc/architecture.md)
- [Cloud.gov Pages](https://cloud.gov/pages/)

### Tools

```bash
# Check DNS resolution
dig spurs.gov A +short
dig spurs.gov AAAA +short
dig www.spurs.gov CNAME +short

# Check DNSSEC
dig spurs.gov +dnssec +short

# Trace DNS path
dig spurs.gov +trace

# Check from specific nameserver
dig @8.8.8.8 spurs.gov A

# Check all records
dig spurs.gov ANY
```

## Support

For DNS-related issues:

- **Documentation**: Review this guide first
- **GitHub Issues**: Create issue in this repository
- **Security Issues**: security@spurs.gov
- **.gov Registry**: https://home.dotgov.gov/help/

---

**Last Updated**: 2025-11-12
**Maintained By**: Infrastructure Team
**Review Frequency**: Quarterly or after major changes
