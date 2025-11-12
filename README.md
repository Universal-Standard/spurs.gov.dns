# spurs.gov.dns

This repository provides **two deployment options** for hosting the `spurs.gov` website:

1. **GitHub Pages** (Recommended for static sites) - Modern, cost-effective, and easy to maintain
2. **AWS Infrastructure** (Legacy) - Full control with EC2, CloudFormation, and traditional hosting

## Quick Start - GitHub Pages

The easiest way to get started is with GitHub Pages:

1. Enable GitHub Pages in repository settings
2. Configure custom domain (`spurs.gov`)
3. Verify domain ownership
4. Configure DNS records

**[📚 Complete GitHub Pages Setup Guide](GITHUB_PAGES_SETUP.md)**

## AWS Infrastructure (Legacy)

This project also contains a CloudFormation template and a setup script to deploy a secure and scalable web infrastructure on AWS for the `spurs.gov` domain.

## GitHub Pages Features

The GitHub Pages deployment includes:

- **U.S. Web Design System (USWDS)**: Professional, accessible design components
- **WCAG 2.1 AA Compliance**: Full accessibility support with Section 508 compliance
- **Automatic HTTPS**: Free SSL/TLS certificates via Let's Encrypt
- **Domain Verification**: Protection against domain takeover attacks
- **Automated CI/CD**: Deployment, accessibility testing, and link checking
- **Security Best Practices**: CSP, security headers, and vulnerability scanning
- **Digital Analytics Program**: Government-wide analytics integration
- **Mobile Responsive**: Works seamlessly on all devices
- **SEO Optimized**: Proper meta tags, sitemap, and semantic HTML

## AWS Infrastructure Features (Legacy)

- **Automated Infrastructure Deployment:** Uses CloudFormation to automate the creation of all necessary AWS resources, including a VPC, subnets, security groups, and an EC2 instance.
- **Secure by Default:** The infrastructure is deployed with security best practices in mind, including:
    - A restrictive firewall that only allows traffic from trusted sources.
    - An IAM role for the EC2 instance to securely access other AWS services.
    - Security headers in the Apache configuration to protect against common web vulnerabilities.
- **Scalable and Flexible:** The CloudFormation template is designed to be scalable and flexible, with parameters that allow you to customize the deployment to your specific needs.

## Repository Structure

```
spurs.gov.dns/
├── index.html                    # Main website homepage
├── CNAME                         # GitHub Pages custom domain
├── 404.html                     # Custom 404 error page
├── privacy.html                 # Privacy policy
├── accessibility.html           # Accessibility statement
├── robots.txt                   # Search engine directives
├── sitemap.xml                  # Site structure
├── assets/                      # Static assets (CSS, JS, images)
├── .well-known/                 # Security and verification files
│   └── security.txt
├── .github/workflows/           # CI/CD automation
│   ├── deploy.yml              # GitHub Pages deployment
│   ├── accessibility.yml       # Accessibility testing
│   └── link-checker.yml        # Link validation
├── GITHUB_PAGES_SETUP.md       # GitHub Pages setup guide
├── SECURITY.md                  # Security policy
├── CODE_OF_CONDUCT.md          # Community guidelines
├── CONTRIBUTING.md             # Contribution guidelines
├── cloudformation.yaml         # AWS deployment (legacy)
└── setup.sh                    # AWS setup script (legacy)
```

## Prerequisites

### For GitHub Pages Deployment

- GitHub account with organization admin access
- Control over `spurs.gov` DNS records
- Basic understanding of Git and GitHub

### For AWS Deployment (Legacy)

- An AWS account
- The AWS CLI installed and configured
- A domain name registered with a domain registrar
- A Cloudflare account

## Deployment Options

### Option 1: GitHub Pages (Recommended)

**Step-by-step guide**: See [GITHUB_PAGES_SETUP.md](GITHUB_PAGES_SETUP.md)

Quick overview:

1. **Enable GitHub Pages**
   - Go to Settings → Pages
   - Set source to `main` branch
   - Save

2. **Verify Domain**
   - Organization Settings → Verified domains
   - Add `spurs.gov`
   - Add TXT record to DNS
   - Verify

3. **Configure DNS**
   ```
   A     @    185.199.108.153
   A     @    185.199.109.153
   A     @    185.199.110.153
   A     @    185.199.111.153
   CNAME www  spurs.gov
   ```

4. **Enable HTTPS**
   - Settings → Pages → Enforce HTTPS
   - Wait for certificate (up to 24 hours)

5. **Deploy**
   - Push to main branch
   - GitHub Actions automatically deploys
   - Site live at https://spurs.gov

**Total Cost**: $0/month (GitHub Pages is free for public repositories)

### Option 2: AWS Infrastructure (Legacy)

To deploy the AWS infrastructure, follow these steps:

1. **Create secrets in AWS Secrets Manager:**

   You need to create two secrets in AWS Secrets Manager:

   - `CloudflareApiToken`: Your Cloudflare API token.
   - `GoogleVerificationCode`: Your Google site verification code.

2. **Deploy the CloudFormation stack:**

   You can deploy the CloudFormation stack using the AWS CLI or the AWS Management Console.

   **Using the AWS CLI:**

   ```bash
   aws cloudformation create-stack \
     --stack-name spurs-gov-stack \
     --template-body file://cloudformation.yaml \
     --parameters \
       ParameterKey=KeyName,ParameterValue=<Your-EC2-Key-Pair-Name> \
       ParameterKey=SshCidrIp,ParameterValue=<Your-Trusted-IP-Range> \
     --capabilities CAPABILITY_IAM
   ```

   Replace `<Your-EC2-Key-Pair-Name>` with the name of your EC2 key pair and `<Your-Trusted-IP-Range>` with the IP address range that you want to allow SSH access from.

   **Using the AWS Management Console:**

   - Open the AWS CloudFormation console.
   - Click "Create stack" and select "With new resources (standard)".
   - Upload the `cloudformation.yaml` file.
   - Enter a name for the stack and fill in the parameters.
   - Click "Next" and then "Create stack".

## `setup.sh` Script

The `setup.sh` script is a user data script that is executed when the EC2 instance is launched. It performs the following tasks:

- Installs and configures Apache, BIND, Postfix, and other necessary software.
- Obtains an SSL certificate from Let's Encrypt using Certbot.
- Configures DNS records in Cloudflare using the Cloudflare API.

The script is designed to be idempotent, which means that it can be run multiple times without causing issues. It also includes error handling to ensure that it exits gracefully if any command fails.
