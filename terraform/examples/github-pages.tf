# Example Terraform configuration for spurs.gov with GitHub Pages
# Following GSA-TTS DNS patterns: https://github.com/gsa-tts/dns

# This is an EXAMPLE file showing how to manage DNS with Terraform
# The current implementation uses direct DNS (no Terraform needed)

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  # Uncomment to use S3 backend (recommended for production)
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "dns/spurs.gov/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-lock"
  # }
}

provider "aws" {
  region = "us-east-1"  # Route 53 is global, but use us-east-1 for consistency
}

# Variables
variable "domain_name" {
  description = "Domain name to manage"
  type        = string
  default     = "spurs.gov"
}

variable "github_verification_code" {
  description = "GitHub domain verification TXT record value"
  type        = string
  sensitive   = true
  # Set via: terraform apply -var="github_verification_code=xxxxx"
  # Or: TF_VAR_github_verification_code environment variable
}

# Create hosted zone for spurs.gov
resource "aws_route53_zone" "spurs_gov_zone" {
  name    = var.domain_name
  comment = "Managed by Terraform - GitHub Pages hosting"

  tags = {
    Project     = "spurs.gov"
    ManagedBy   = "Terraform"
    Environment = "production"
    Purpose     = "GitHub Pages DNS"
  }
}

# A records pointing to GitHub Pages
# GitHub Pages IPs as of 2024
resource "aws_route53_record" "spurs_gov_github_pages_a" {
  for_each = toset([
    "185.199.108.153",
    "185.199.109.153",
    "185.199.110.153",
    "185.199.111.153"
  ])

  zone_id = aws_route53_zone.spurs_gov_zone.zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 3600
  records = [each.value]
}

# CNAME record for www subdomain
resource "aws_route53_record" "spurs_gov_www_cname" {
  zone_id = aws_route53_zone.spurs_gov_zone.zone_id
  name    = "www.${var.domain_name}"
  type    = "CNAME"
  ttl     = 3600
  records = [var.domain_name]
}

# GitHub domain verification TXT record
# Prevents domain takeover attacks
resource "aws_route53_record" "spurs_gov_github_verification" {
  zone_id = aws_route53_zone.spurs_gov_zone.zone_id
  name    = "_github-challenge-ORGNAME-DOMAIN.${var.domain_name}"
  type    = "TXT"
  ttl     = 300  # Low TTL during verification
  records = [var.github_verification_code]

  lifecycle {
    # Prevent accidental deletion of critical security record
    prevent_destroy = true
  }
}

# CAA records to restrict certificate issuance
# Allows only Let's Encrypt (used by GitHub Pages)
resource "aws_route53_record" "spurs_gov_caa_letsencrypt" {
  zone_id = aws_route53_zone.spurs_gov_zone.zone_id
  name    = var.domain_name
  type    = "CAA"
  ttl     = 3600
  records = [
    "0 issue \"letsencrypt.org\"",
    "0 issue \"pki.goog\"",  # Google Trust Services (backup)
    "0 iodef \"mailto:security@spurs.gov\""
  ]
}

# Optional: DNSSEC signing
# Note: This requires additional setup and KMS keys
# Uncomment if you want DNSSEC
#
# resource "aws_route53_key_signing_key" "spurs_gov_ksk" {
#   hosted_zone_id             = aws_route53_zone.spurs_gov_zone.zone_id
#   key_management_service_arn = aws_kms_key.dnssec.arn
#   name                       = "spurs-gov-ksk"
# }
#
# resource "aws_route53_hosted_zone_dnssec" "spurs_gov_dnssec" {
#   hosted_zone_id = aws_route53_key_signing_key.spurs_gov_ksk.hosted_zone_id
# }

# Outputs - Important for domain configuration
output "spurs_gov_nameservers" {
  description = "Nameservers to configure at .gov registrar"
  value       = aws_route53_zone.spurs_gov_zone.name_servers
}

output "spurs_gov_zone_id" {
  description = "Route 53 hosted zone ID"
  value       = aws_route53_zone.spurs_gov_zone.zone_id
}

output "spurs_gov_configuration_instructions" {
  description = "Instructions for completing DNS setup"
  value = <<-EOT
    
    ========================================
    DNS Configuration Complete!
    ========================================
    
    Next steps:
    
    1. Update nameservers at your .gov registrar:
       ${join("\n       ", aws_route53_zone.spurs_gov_zone.name_servers)}
    
    2. Wait 24-72 hours for DNS propagation
    
    3. Verify with: dig spurs.gov NS
    
    4. Enable GitHub Pages:
       - Repository Settings → Pages
       - Set custom domain: spurs.gov
       - Wait for DNS check to pass
       - Enable HTTPS enforcement
    
    5. Verify domain in GitHub organization:
       - Organization Settings → Verified domains
       - Verify spurs.gov
       - Protects against domain takeover
    
    6. Test site at: https://spurs.gov
    
    ========================================
    EOT
}

# Health check for the domain (optional but recommended)
# This monitors if the site is accessible
resource "aws_route53_health_check" "spurs_gov_https" {
  fqdn              = var.domain_name
  port              = 443
  type              = "HTTPS"
  resource_path     = "/"
  failure_threshold = 3
  request_interval  = 30

  tags = {
    Name = "spurs.gov-https-health-check"
  }
}

# CloudWatch alarm for health check failures
resource "aws_cloudwatch_metric_alarm" "spurs_gov_health" {
  alarm_name          = "spurs-gov-site-down"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthCheckStatus"
  namespace           = "AWS/Route53"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Alert when spurs.gov is unreachable"
  
  dimensions = {
    HealthCheckId = aws_route53_health_check.spurs_gov_https.id
  }

  # Uncomment to enable SNS notifications
  # alarm_actions = [aws_sns_topic.alerts.arn]
}

# Example: Query logs (requires CloudWatch Logs setup)
# Useful for debugging DNS issues
#
# resource "aws_route53_query_log" "spurs_gov_logs" {
#   zone_id                  = aws_route53_zone.spurs_gov_zone.zone_id
#   cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns_logs.arn
# }
#
# resource "aws_cloudwatch_log_group" "dns_logs" {
#   name              = "/aws/route53/spurs.gov"
#   retention_in_days = 7
# }
