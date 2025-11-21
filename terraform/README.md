# Terraform DNS Configuration (Optional)

This directory contains optional Terraform configurations for managing spurs.gov DNS via AWS Route 53, following GSA-TTS patterns.

## Current Status

**DNS is currently managed directly** via DNS provider pointing to GitHub Pages. Terraform configuration here is **optional** and provided for organizations that want Infrastructure as Code DNS management.

## When to Use Terraform

Consider Terraform + Route 53 if you need:

- ✅ Multiple domains managed centrally
- ✅ Complex DNS configurations
- ✅ Git-based change tracking and peer review
- ✅ Automated DNS deployments via CI/CD
- ✅ DNSSEC with full control
- ✅ Integration with other AWS services

## When to Skip Terraform

Stick with direct DNS management if:

- ✅ Single domain (spurs.gov only)
- ✅ Simple DNS needs (just GitHub Pages)
- ✅ Want to minimize costs ($0 vs ~$0.50/month)
- ✅ Prefer simplicity over flexibility
- ✅ No AWS infrastructure

## Setup (If Using Terraform)

### 1. Install Prerequisites

```bash
# Install Terraform
brew install terraform  # macOS
# or download from https://www.terraform.io/downloads

# Configure AWS credentials
aws configure
```

### 2. Initialize Terraform

```bash
cd terraform
terraform init
```

### 3. Review Configuration

```bash
terraform plan
```

### 4. Apply Changes

```bash
terraform apply
```

### 5. Update Domain Nameservers

After applying, Terraform outputs nameservers:

```bash
terraform output spurs_gov_ns
```

Update these at your .gov registrar (https://manage.get.gov/).

## File Structure

```
terraform/
├── README.md              # This file
├── spurs.gov.tf          # Main DNS configuration
├── variables.tf          # Input variables
├── outputs.tf            # Output values
├── backend.tf            # State storage config
└── examples/
    └── github-pages.tf   # Example GitHub Pages setup
```

## Example Configuration

See `examples/github-pages.tf` for a complete example of managing GitHub Pages DNS with Terraform.

## GSA-TTS Pattern

This follows the pattern used by GSA-TTS:
- [GSA-TTS DNS Repository](https://github.com/gsa-tts/dns)
- [Architecture Documentation](https://github.com/gsa-tts/dns/blob/main/doc/architecture.md)

Key principles:
1. **All changes via Pull Request**
2. **Peer review required**
3. **Automated validation** (terraform validate)
4. **Automated deployment** (terraform apply in CI)
5. **Change notifications** (Slack/email)

## CI/CD Integration

If using Terraform, add to `.github/workflows/`:

```yaml
# .github/workflows/terraform.yml
name: Terraform DNS

on:
  pull_request:
    paths:
      - 'terraform/**'
  push:
    branches:
      - main
    paths:
      - 'terraform/**'

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      
      - name: Terraform Init
        run: terraform init
        
      - name: Terraform Validate
        run: terraform validate
        
      - name: Terraform Plan
        run: terraform plan
        
      - name: Terraform Apply
        if: github.ref == 'refs/heads/main'
        run: terraform apply -auto-approve
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## Cost Comparison

| Component | Direct DNS | Terraform + Route 53 |
|-----------|-----------|---------------------|
| Hosted Zone | $0 | $0.50/month |
| Queries (first 1B) | $0 | $0.40/million |
| **Monthly Total** | **$0** | **~$0.50** |
| **Annual Total** | **$0** | **~$6.00** |

## Migration Path

### From Direct DNS to Terraform

1. Create Terraform config matching current DNS
2. Test with `terraform plan`
3. Import existing records (if any in Route 53)
4. Apply Terraform configuration
5. Update nameservers at registrar
6. Verify DNS resolution
7. Remove old DNS provider config

### From Terraform to Direct DNS

1. Note current Route 53 nameservers
2. Configure direct DNS records at provider
3. Update nameservers at registrar
4. Wait for propagation (24-72 hours)
5. Verify resolution
6. Destroy Route 53 resources

## Support

- **Terraform Issues**: Create issue in this repository
- **AWS Route 53**: AWS Support or documentation
- **GSA-TTS Pattern**: See their repository for examples

## References

- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Route 53 Documentation](https://docs.aws.amazon.com/route53/)
- [GSA-TTS DNS Repo](https://github.com/gsa-tts/dns)
- [Terraform Best Practices](https://www.terraform-best-practices.com/)

---

**Note**: This is optional infrastructure. The repository works perfectly without Terraform.
