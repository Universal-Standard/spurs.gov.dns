#!/bin/bash
set -e

# Refactored script for setting up the spurs.gov environment

# --- Configuration ---
DOMAIN="spurs.gov"
ADMIN_EMAIL="admin@${DOMAIN}"
CLOUDFLARE_API_TOKEN_SECRET_NAME="CloudflareApiToken"
GOOGLE_VERIFICATION_CODE_SECRET_NAME="GoogleVerificationCode"
REGION="us-east-1" # Or get from instance metadata

# --- Helper Functions ---
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

get_secret() {
    aws secretsmanager get-secret-value --secret-id "$1" --region "$REGION" --query SecretString --output text
}

# --- Main Script ---

log "Starting setup for ${DOMAIN}"

# --- Install necessary packages ---
log "Updating and installing packages..."
yum update -y
yum install -y httpd bind bind-utils mod_ssl certbot python3-certbot-apache postfix mailx dovecot

# --- Configure Hostname ---
log "Configuring hostname..."
hostnamectl set-hostname "server.${DOMAIN}"

# --- Configure Apache ---
log "Configuring Apache..."
cat <<EOF > /etc/httpd/conf.d/vhost.conf
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias www.${DOMAIN}
    DocumentRoot /var/www/html
    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</VirtualHost>
EOF

# Add security headers
cat <<EOF > /etc/httpd/conf.d/security.conf
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
EOF

systemctl enable httpd
systemctl start httpd

# --- Obtain SSL Certificate ---
log "Obtaining SSL certificate with Certbot..."
certbot --apache -d "${DOMAIN}" -d "www.${DOMAIN}" --non-interactive --agree-tos --email "${ADMIN_EMAIL}"

# --- Configure BIND ---
log "Configuring BIND..."
SERVER_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

cat <<EOF > /etc/named.conf.local
zone "${DOMAIN}" {
    type master;
    file "/etc/named/zones/${DOMAIN}.zone";
};
EOF

mkdir -p /etc/named/zones

cat <<EOF > /etc/named/zones/${DOMAIN}.zone
\$TTL 86400
@   IN  SOA ns1.${DOMAIN}. admin.${DOMAIN}. (
        $(date +%Y%m%d%S) ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        86400       ; Negative Cache TTL
)
@       IN  NS  ns1.${DOMAIN}.
ns1     IN  A   ${SERVER_IP}
www     IN  CNAME   @
@       IN  A   ${SERVER_IP}
EOF

systemctl enable named
systemctl start named

# --- Configure Postfix ---
log "Configuring Postfix..."
postconf -e "myhostname = mail.${DOMAIN}"
postconf -e "mydomain = ${DOMAIN}"
postconf -e "myorigin = ${DOMAIN}"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = all"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"

systemctl enable postfix
systemctl start postfix

# --- Configure Cloudflare ---
log "Configuring Cloudflare..."
CLOUDFLARE_API_TOKEN=$(get_secret "${CLOUDFLARE_API_TOKEN_SECRET_NAME}")
GOOGLE_VERIFICATION_CODE=$(get_secret "${GOOGLE_VERIFICATION_CODE_SECRET_NAME}")

pip3 install cloudflare

cat <<EOF > /root/cloudflare_setup.py
import CloudFlare
import os

cf = CloudFlare.CloudFlare(token=os.environ['CLOUDFLARE_API_TOKEN'])
domain_name = os.environ['DOMAIN']
server_ip = os.environ['SERVER_IP']
google_verification = os.environ['GOOGLE_VERIFICATION_CODE']

try:
    zone_info = cf.zones.post(data={'name': domain_name, 'jump_start': False})
    zone_id = zone_info['id']

    dns_records = [
        {'type': 'A', 'name': '@', 'content': server_ip},
        {'type': 'A', 'name': 'www', 'content': server_ip},
        {'type': 'A', 'name': 'ns1', 'content': server_ip},
        {'type': 'MX', 'name': '@', 'content': 'aspmx.l.google.com.', 'priority': 1},
        {'type': 'MX', 'name': '@', 'content': 'alt1.aspmx.l.google.com.', 'priority': 5},
        {'type': 'MX', 'name': '@', 'content': 'alt2.aspmx.l.google.com.', 'priority': 5},
        {'type': 'MX', 'name': '@', 'content': 'alt3.aspmx.l.google.com.', 'priority': 10},
        {'type': 'MX', 'name': '@', 'content': 'alt4.aspmx.l.google.com.', 'priority': 10},
        {'type': 'TXT', 'name': '@', 'content': google_verification}
    ]

    for record in dns_records:
        cf.zones.dns_records.post(zone_id, data=record)

    print(f"Successfully configured DNS for {domain_name}")

except CloudFlare.exceptions.CloudFlareAPIError as e:
    print(f"Error: {e}")

EOF

export DOMAIN SERVER_IP CLOUDFLARE_API_TOKEN GOOGLE_VERIFICATION_CODE
python3 /root/cloudflare_setup.py

log "Setup script finished."
