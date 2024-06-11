AWSTemplateFormatVersion: '2010-09-09'
Description: 'Setup for spurs.gov including DNS, cPanel, SSL, and email configuration using Cloudflare and Google Workspace.'

Parameters:
  KeyName:
    Description: 'Name of an existing EC2 KeyPair to enable SSH access to the instance'
    Type: 'AWS::EC2::KeyPair::KeyName'

Resources:
  SpursGovInstance:
    Type: 'AWS::EC2::Instance'
    Properties: 
      InstanceType: t2.micro
      KeyName: !Ref KeyName
      ImageId: ami-0c55b159cbfafe1f0  # Amazon Linux 2 AMI
      NetworkInterfaces:
        - AssociatePublicIpAddress: true
          DeviceIndex: 0
          SubnetId: !Ref PublicSubnet
          GroupSet:
            - !Ref SpursGovSecurityGroup
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          set -e
          DOMAIN="spurs.gov"
          GOOGLE_VERIFICATION_CODE="google-site-verification=87-A3TdKki7swEGkz0Cnfm7cso16EBdIQ9SNtgmgVm4"
          CLOUDFLARE_API_TOKEN="YOUR_CLOUDFLARE_API_TOKEN"

          # Update and install necessary packages
          yum update -y
          yum install -y bind bind-utils httpd mysql-server php perl mutt exim mailx postfix dovecot vsftpd iptables fail2ban ufw logwatch logrotate certbot nmap python3-pip

          # Install cPanel
          cd /home && curl -o latest -L https://securedownloads.cpanel.net/latest && sh latest

          # Configure hostname
          hostnamectl set-hostname $DOMAIN

          # Get IP addresses
          IPV4=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
          IPV6=$(curl -s http://169.254.169.254/latest/meta-data/ipv6)

          echo "$IPV4 $DOMAIN" >> /etc/hosts
          echo "$IPV6 $DOMAIN" >> /etc/hosts

          # Set root password
          echo "root:changethis" | chpasswd

          # Configure MySQL root password
          MYSQL_ROOT_PASSWORD="changethis"
          echo "[client]
          user=root
          password=$MYSQL_ROOT_PASSWORD" > /root/.my.cnf

          # Configure Exim
          sed -i "s/dc_other_hostnames=''/dc_other_hostnames='$DOMAIN'/" /etc/exim4/update-exim4.conf.conf
          sed -i "s/127.0.0.1/$IPV4/" /etc/exim4/exim.conf

          # Configure Postfix
          postconf -e "myhostname = $DOMAIN"
          postconf -e "mydomain = $DOMAIN"
          postconf -e "myorigin = $DOMAIN"
          postconf -e "inet_interfaces = all"
          postconf -e "inet_protocols = all"

          # Configure BIND DNS
          cat <<EOF > /etc/named.conf.local
          zone "$DOMAIN" {
              type master;
              file "/etc/bind/zones/$DOMAIN.zone";
          };

          zone "$IPV4.in-addr.arpa" {
              type master;
              file "/etc/bind/zones/$IPV4.in-addr.arpa.zone";
          };

          zone "$IPV6.in-addr.arpa" {
              type master;
              file "/etc/bind/zones/$IPV6.in-addr.arpa.zone";
          };
          EOF

          # Create zone files
          mkdir -p /etc/bind/zones
          cat <<EOF > /etc/bind/zones/$DOMAIN.zone
          \$TTL 86400
          @   IN  SOA ns1.$DOMAIN. hostmaster.$DOMAIN. (
              2023010101  ; Serial
              3600        ; Refresh
              1800        ; Retry
              604800      ; Expire
              86400 )     ; Negative Cache TTL
          @       IN  NS  ns1.$DOMAIN.
          @       IN  NS  ns2.$DOMAIN.
          ns1     IN  A   $IPV4
          ns2     IN  A   $IPV6
          www     IN  CNAME   @
          @       IN  MX  1   aspmx.l.google.com.
          @       IN  MX  5   alt1.aspmx.l.google.com.
          @       IN  MX  5   alt2.aspmx.l.google.com.
          @       IN  MX  10  alt3.aspmx.l.google.com.
          @       IN  MX  10  alt4.aspmx.l.google.com.
          @       IN  TXT "$GOOGLE_VERIFICATION_CODE"
          _dmarc  IN  TXT "v=DMARC1; p=none; pct=100; rua=mailto:dmarcreports@$DOMAIN"
          mail._domainkey IN TXT "$(cat /etc/opendkim/keys/$DOMAIN/mail.txt)"
          EOF

          cat <<EOF > /etc/bind/zones/$IPV4.in-addr.arpa.zone
          \$TTL 86400
          @   IN  SOA ns1.$DOMAIN. hostmaster.$DOMAIN. (
              2023010101  ; Serial
              3600        ; Refresh
              1800        ; Retry
              604800      ; Expire
              86400 )     ; Negative Cache TTL
          @       IN  NS  ns1.$DOMAIN.
          @       IN  NS  ns2.$DOMAIN.
          1       IN  PTR ns1.$DOMAIN.
          EOF

          cat <<EOF > /etc/bind/zones/$IPV6.in-addr.arpa.zone
          \$TTL 86400
          @   IN  SOA ns1.$DOMAIN. hostmaster.$DOMAIN. (
              2023010101  ; Serial
              3600        ; Refresh
              1800        ; Retry
              604800      ; Expire
              86400 )     ; Negative Cache TTL
          @       IN  NS  ns1.$DOMAIN.
          @       IN  NS  ns2.$DOMAIN.
          1       IN  PTR ns2.$DOMAIN.
          EOF

          systemctl restart bind9

          # Setup SPF, DKIM, and DMARC
          apt install opendkim opendkim-tools -y
          mkdir -p /etc/opendkim/keys/$DOMAIN
          opendkim-genkey -b 2048 -d $DOMAIN -D /etc/opendkim/keys/$DOMAIN -s mail -v
          mv /etc/opendkim/keys/$DOMAIN/mail.private /etc/opendkim/keys/$DOMAIN/mail
          chown -R opendkim:opendkim /etc/opendkim/keys/$DOMAIN

          cat <<EOF > /etc/opendkim.conf
          KeyTable    /etc/opendkim/keytable
          SigningTable    refile:/etc/opendkim/keytable
          ExternalIgnoreList   refile:/etc/opendkim/trustedhosts
          InternalHosts        refile:/etc/opendkim/trustedhosts
          Mode            sv
          PidFile         /var/run/opendkim/opendkim.pid
          Socket          inet:8891@localhost
          UMask           002
          Syslog          yes
          UserID          opendkim:opendkim
          EOF

          cat <<EOF > /etc/opendkim/keytable
          mail._domainkey.$DOMAIN $DOMAIN:mail:/etc/opendkim/keys/$DOMAIN/mail
          EOF

          cat <<EOF > /etc/opendkim/trustedhosts
          127.0.0.1
          localhost
          $DOMAIN
          EOF

          systemctl restart opendkim
          systemctl restart postfix

          cat <<EOF >> /etc/named/zones/$DOMAIN.zone
          _dmarc IN TXT "v=DMARC1; p=none; pct=100; rua=mailto:dmarcreports@$DOMAIN"
          mail._domainkey IN TXT "$(cat /etc/opendkim/keys/$DOMAIN/mail.txt)"
          EOF

          systemctl restart named

          # Install and configure Certbot for SSL
          apt install certbot python3-certbot-apache -y
          certbot --apache -d $DOMAIN

          # Redirect HTTP to HTTPS
          cat <<EOF > /etc/apache2/sites-available/redirect-http-to-https.conf
          <VirtualHost *:80>
              ServerName $DOMAIN
              Redirect "/" "https://$DOMAIN/"
          </VirtualHost>
          EOF

          a2ensite redirect-http-to-https.conf
          systemctl reload apache2

          # Setup Cloudflare API integration
          pip3 install cloudflare
          
          # Cloudflare setup
          cat <<EOF > /root/cloudflare_setup.py
          import CloudFlare
          cf = CloudFlare.CloudFlare(token='$CLOUDFLARE_API_TOKEN')
          domain_name = '$DOMAIN'
          ns1_ip = '$IPV4'
          ns2_ip = '$IPV6'

          # Create zone
          zone = cf.zones.post(data={'name': domain_name})
          zone_id = zone['result']['id']
          
          # Create DNS records
          cf.zones.dns_records.post(zone_id, data={'type': 'A', 'name': 'ns1', 'content': ns1_ip, 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'A', 'name': 'ns2', 'content': ns2_ip, 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'MX', 'name': domain_name, 'content': 'aspmx.l.google.com', 'priority': 1, 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'MX', 'name': domain_name, 'content': 'alt1.aspmx.l.google.com', 'priority': 5, 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'MX', 'name': domain_name, 'content': 'alt2.aspmx.l.google.com', 'priority': 5, 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'MX', 'name': domain_name, 'content': 'alt3.aspmx.l.google.com', 'priority': 10, 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'MX', 'name': domain_name, 'content': 'alt4.aspmx.l.google.com', 'priority': 10, 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'TXT', 'name': domain_name, 'content': '$GOOGLE_VERIFICATION_CODE', 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'TXT', 'name': '_dmarc', 'content': 'v=DMARC1; p=none; pct=100; rua=mailto:dmarcreports@$DOMAIN', 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'TXT', 'name': 'mail._domainkey', 'content': "$(cat /etc/opendkim/keys/$DOMAIN/mail.txt)", 'proxied': False})

          # Set NS records
          cf.zones.dns_records.post(zone_id, data={'type': 'NS', 'name': domain_name, 'content': 'ns1.$domain_name', 'proxied': False})
          cf.zones.dns_records.post(zone_id, data={'type': 'NS', 'name': domain_name, 'content': 'ns2.$domain_name', 'proxied': False})
          EOF

          python3 /root/cloudflare_setup.py

          # Ensure resolv.conf is set up correctly
          cat <<EOF > /etc/resolv.conf
          nameserver 127.0.0.1
          nameserver 146.190.122.84
          nameserver 24.199.79.198
          nameserver 1.1.1.1
          nameserver 1.0.0.1
          nameserver 8.8.8.8
          nameserver 8.8.4.4
          nameserver 64.6.64.6
          nameserver 64.6.65.6
          options rotate
          EOF

          # Restart networking
          systemctl restart networking

Outputs:
  SpursGovInstanceId:
    Description: 'Instance ID of the newly created instance'
    Value: !Ref SpursGovInstance

#!/bin/bash

# Title: AWS CloudFormation Script for Spurs.gov Domain Setup

# This script will set up the spurs.gov domain on AWS, configure DNS records using Cloudflare API, and install necessary software and configurations.

# Update and upgrade the system
apt-get update && apt-get upgrade -y

# Install required packages
apt-get install -y bind9 apache2 mysql-server php perl mutt exim4 postfix dovecot-imapd dovecot-pop3d ftp vsftpd sendmail iptables fail2ban ufw logwatch logrotate certbot nmap duplicity python3-pip

# Install Cloudflare API client
pip3 install cloudflare

# Set up environment variables
DOMAIN="spurs.gov"
GOOGLE_VERIFICATION_CODE="google-site-verification=87-A3TdKki7swEGkz0Cnfm7cso16EBdIQ9SNtgmgVm4"
NS1_IP="146.190.122.84"
NS2_IP="24.199.79.198"

# Install cPanel
cd /home
curl -o latest -L https://securedownloads.cpanel.net/latest
sh latest

# Get dynamic server information
SERVER_IP=$(hostname -I | awk '{print $1}')
SERVER_IPV6=$(ip -6 addr show eth0 | awk '/inet6/{print $2}' | sed 's/\/.*//')

# Configure hostname
hostnamectl set-hostname $DOMAIN
echo "$SERVER_IP $DOMAIN" >> /etc/hosts
echo "$SERVER_IPV6 $DOMAIN" >> /etc/hosts

# Set root password
echo "root:changethis" | chpasswd

# Configure network
echo "HOSTNAME=$DOMAIN" >> /etc/sysconfig/network
ifdown eth0 && ifup eth0

# Configure MySQL root password
MYSQL_ROOT_PASSWORD="changethis"
echo "mysql-root-password=$MYSQL_ROOT_PASSWORD" > /root/.my.cnf

# Configure Exim
sed -i "s/PRIMARY_HOSTNAME=/PRIMARY_HOSTNAME=$DOMAIN/" /etc/exim4/update-exim4.conf.conf
sed -i "s/dc_other_hostnames='/dc_other_hostnames=$DOMAIN "/etc/exim4/update-exim4.conf.conf
sed -i "s/127.0.0.1/$SERVER_IP/" /etc/exim4/exim.conf

# Configure Postfix
postconf -e "myhostname = $DOMAIN"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = $DOMAIN"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = all"

# Configure BIND DNS
cat <<EOF > /etc/bind/named.conf.local
// Define zones
zone "$DOMAIN" IN {
    type master;
    file "/etc/bind/db.$DOMAIN";
};

zone "$SERVER_IP.in-addr.arpa" {
    type master;
    file "/etc/bind/db.$SERVER_IP";
};

zone "$SERVER_IPV6.in-addr.arpa" {
    type master;
    file "/etc/bind/db.$SERVER_IPV6";
};

// Allow queries
acl "trusted" {
    $SERVER_IP;
    localhost;
    localnets;
};

options {
    directory "/var/cache/bind";

    allow-query { trusted; };

    recursion yes;
    allow-recursion { trusted; };

    dnssec-validation auto;

    auth-nxdomain no;
    listen-on { any; };
};
EOF

# Create zone files
cat <<EOF > /etc/bind/db.$DOMAIN
\$TTL    604800
@       IN      SOA     $DOMAIN. root.$DOMAIN. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMAIN.
@       IN      NS      ns2.$DOMAIN.
@       IN      A       $SERVER_IP
@       IN      AAAA    $SERVER_IPV6
www     IN      CNAME   @
EOF

cat <<EOF > /etc/bind/db.$SERVER_IP
\$TTL    604800
@       IN      SOA     $DOMAIN. root.$DOMAIN. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      PTR     $DOMAIN.
EOF

cat <<EOF > /etc/bind/db.$SERVER_IPV6
\$TTL    604800
@       IN      SOA     $DOMAIN. root.$DOMAIN. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      PTR     $DOMAIN.
EOF

systemctl restart bind9

# Configure Apache virtual hosts
cat <<EOF > /etc/apache2/sites-available/$DOMAIN.conf
<VirtualHost *:80>
  ServerName $DOMAIN
  ServerAlias www.$DOMAIN
  DocumentRoot /var/www/$DOMAIN/public_html
  ErrorLog /var/www/$DOMAIN/logs/error.log
  CustomLog /var/www/$DOMAIN/logs/access.log combined
</VirtualHost>
EOF
a2ensite $DOMAIN.conf

# Configure Apache for SSL
a2enmod ssl
a2ensite default-ssl
systemctl restart apache2

# Obtain and install SSL certificate
certbot --apache -d $DOMAIN

# Redirect HTTP to HTTPS
cat <<EOF > /etc/apache2/sites-available/redirect.conf
<VirtualHost *:80>
  ServerName $DOMAIN
  Redirect "/" "https://$DOMAIN/"
</VirtualHost>
EOF
a2ensite redirect.conf
systemctl reload apache2

# Configure firewall - UFW
ufw allow ssh
ufw allow http
ufw allow https
ufw allow 21
ufw allow 587/tcp
ufw allow 465/tcp
ufw allow 110/tcp
ufw allow 143/tcp
ufw allow pop3s
ufw enable

# IPTables rules
iptables -A INPUT -p tcp --dport 25 -j ACCEPT
iptables -A INPUT -p tcp --dport 110 -j ACCEPT
iptables -A INPUT -p tcp --dport 143 -j ACCEPT
iptables -A INPUT -p tcp --dport 465 -j ACCEPT
iptables -A INPUT -p tcp --dport 587 -j ACCEPT
iptables -A INPUT -p tcp --dport 993 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
service iptables save

# Install and configure SpamAssassin
apt-get install spamassassin -y
sed -i 's/RequiredHits 5/RequiredHits 3/' /etc/spamassassin/local.cf
sed -i 's/rewrite_header Subject [SPAM]/rewrite_header Subject ***SPAM***/' /etc/spamassassin/local.cf

# Install ClamAV and configure
apt-get install clamav clamav-daemon -y
freshclam
echo "LocalSocket /var/run/clamav/clamd.ctl" >> /etc/clamav/clamd.conf
systemctl restart clamav-daemon

# Install and configure Postgrey
apt-get install postgrey -y
sed -i 's/inet_interfaces = all/inet_interfaces = 127.0.0.1/g' /etc/postfix/main.cf
sed -i 's/smtpd_client_restrictions =/smtpd_client_restrictions = check_policy_service inet:127.0.0.1:10023/g' /etc/postfix/main.cf
systemctl restart postfix

# Configure Postfix for outbound relay via Google Workspace
postconf -e 'relayhost = [smtp.gmail.com]:587'
postconf -e 'smtp_sasl_auth_enable = yes'
postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
postconf -e 'smtp_sasl_security_options = noanonymous'
postconf -e 'smtp_use_tls = yes'
postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'
echo "[smtp.gmail.com]:587 you@gmail.com:password" > /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
systemctl reload postfix

# Configure Exim outbound relay
echo "smarthost = smtp.gmail.com::587" >> /etc/exim4/exim4.conf.localmacros
echo "hide mysql_servers = 127.0.0.1/32" >> /etc/exim4/exim4.conf.localmacros

# Create DNS records script for Cloudflare
cat <<EOF > /root/scripts/cloudflare_dns_setup.sh
#!/bin/bash

# Cloudflare API details
CLOUDFLARE_API_KEY="your_cloudflare_api_key"
CLOUDFLARE_EMAIL="your_cloudflare_email"
ZONE_ID="your_zone_id"

# Create DNS records
curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"spurs.gov","content":"$SERVER_IP","ttl":120,"proxied":false}'

curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"AAAA","name":"spurs.gov","content":"$SERVER_IPV6","ttl":120,"proxied":false}'

curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"MX","name":"spurs.gov","content":"aspmx.l.google.com","priority":1,"ttl":120,"proxied":false}'

curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"MX","name":"spurs.gov","content":"alt1.aspmx.l.google.com","priority":5,"ttl":120,"proxied":false}'

curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"MX","name":"spurs.gov","content":"alt2.aspmx.l.google.com","priority":5,"ttl":120,"proxied":false}'

curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"MX","name":"spurs.gov","content":"alt3.aspmx.l.google.com","priority":10,"ttl":120,"proxied":false}'

curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"MX","name":"spurs.gov","content":"alt4.aspmx.l.google.com","priority":10,"ttl":120,"proxied":false}'

curl -X POST "https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records" \
     -H "X-Auth-Email: \$CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: \$CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"type":"TXT","name":"spurs.gov","content":"$GOOGLE_VERIFICATION_CODE","ttl":120,"proxied":false}'
EOF

chmod +x /root/scripts/cloudflare_dns_setup.sh
/root/scripts/cloudflare_dns_setup.sh

# Install and configure OpenLDAP
apt-get install slapd ldap-utils -y
dpkg-reconfigure slapd

# Configure OpenLDAP TLS
sed -i 's/#TLS_REQCERT.*/TLS_REQCERT demand/' /etc/ldap/ldap.conf
echo "TLS_CACERT /etc/ssl/certs/ca-certificates.crt" >> /etc/ldap/ldap.conf

# Install SSL certificate
certbot certonly --standalone -d $DOMAIN

# Configure Apache to use SSL
a2enmod ssl
a2ensite default-ssl

cat <<EOF > /etc/apache2/sites-available/default-ssl.conf
<IfModule mod_ssl.c>
<VirtualHost *:443>
  ServerName $DOMAIN
  DocumentRoot /var/www/html

  SSLEngine on
  SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem
  SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem

  # Additional SSL directives here

</VirtualHost>
</IfModule>
EOF

# Redirect HTTP to HTTPS
cat <<EOF > /etc/apache2/sites-available/redirect-http-to-https.conf
<VirtualHost *:80>
  ServerName $DOMAIN
  Redirect "/" "https://$DOMAIN/"
</VirtualHost>
EOF

a2ensite redirect-http-to-https.conf

# Restart Apache
systemctl restart apache2

# Configure firewall
ufw allow 53
ufw allow 25/tcp
ufw allow 587/tcp
ufw allow 465/tcp
ufw allow 110/tcp
ufw allow 143/tcp
ufw allow 443/tcp

# Install web content management system
apt-get install wordpress -y

# Configure WordPress
mv /etc/wordpress/config-localhost.php /etc/wordpress/config-$DOMAIN.php
sed -i "s/localhost/$DOMAIN/g" /etc/wordpress/config-$DOMAIN.php

# Set permissions
chown -R www-data:www-data /var/www/html

# Restart services
systemctl restart apache2
systemctl restart mysql

# Create cron jobs
# Daily backup
echo "0 0 * * * mysqldump -u root -p$MYSQL_ROOT_PASSWORD companydb > /root/dbbackups/companydb-\$(date +%Y%m%d).sql" >> /etc/crontab

# Weekly cleanup
echo "0 0 * * 0 rm -f /root/dbbackups/*.sql.??*" >> /etc/crontab

echo "Setup for $DOMAIN complete!"

# Setup user accounts
useradd -m user1
useradd -m user2

# Set passwords
echo "user1:password1" | chpasswd
echo "user2:password2" | chpasswd

# Give sudo access
usermod -aG sudo user1

# Copy ssh keys for passwordless login
ssh-copy-id user1@$DOMAIN
ssh-copy-id user2@$DOMAIN

# Configure sshd
sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Install web server monitoring
apt-get install nagios4 -y

# Configure Nagios
htpasswd -c /etc/nagios4/htpasswd.users nagiosadmin

cat <<EOF > /etc/nagios4/cgi.cfg
authorized_for_system_information=nagiosadmin
authorized_for_configuration_information=nagiosadmin
authorized_for_system_commands=nagiosadmin
authorized_for_all_services=nagiosadmin
authorized_for_all_hosts=nagiosadmin
authorized_for_all_service_commands=nagiosadmin
authorized_for_all_host_commands=nagiosadmin
EOF

systemctl restart apache2
systemctl restart nagios4

# Install intrusion detection
apt-get install snort -y

# Configure Snort
cat <<EOF > /etc/snort/snort.conf
# Snort configuration

ipvar HOME_NET $DOMAIN/24

var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preprocessors

var WHITE_LIST_PATH /etc/snort/rules/whitelist
var BLACK_LIST_PATH /etc/snort/rules/blacklist

var DNS_SERVERS [$SERVER_IP]

var HTTP_PORTS 80
var SHELLCODE_PORTS !80

var ARP_SPOOF src & ARP_SPOOF dst

# Additional Snort directives here
EOF

systemctl restart snort

# Set up log monitoring
apt-get install logwatch -y

echo "Logwatch configured successfully!"

# Set up automatic security updates
apt-get install unattended-upgrades -y

cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "${DOMAIN//./\\.}";
};
EOF

dpkg-reconfigure --priority=low unattended-upgrades

# Enable automatic updates
systemctl enable unattended-upgrades.service

# Configure logrotate
cat <<EOF >> /etc/logrotate.conf

/var/log/apache2/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
}

/var/log/syslog {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
}

/var/log/auth.log {
    daily
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
}
EOF

# Set up partitions
(
    echo o; echo n; echo p; echo 1; echo; echo; echo w;
) | fdisk /dev/vda

mkfs.ext4 /dev/vda1
echo "/dev/vda1  /data ext4    defaults    1  1" >> /etc/fstab
mount -a
chmod 775 /data

# Configure log directories
mkdir /data/logs
chmod 775 /data/logs
mv /var/log/* /data/logs/
ln -s /data/logs/* /var/log/

# Set up swap file
fallocate -l 2G /data/swapfile
chmod 600 /data/swapfile
mkswap /data/swapfile
swapon /data/swapfile
echo "/data/swapfile none swap sw 0 0" >> /etc/fstab

echo "Server configuration complete!"

# Configure email security
apt-get install postfix-policyd-spf-python -y
echo "policy_time_limit = 3600" >> /etc/postfix-policyd-spf-python/policyd-spf.conf

postconf -e "smtpd_client_restrictions = check_policy_service inet:127.0.0.1:10023"

systemctl restart postfix

# Set SPF records
cat <<EOF >> /var/named/spurs.gov.zone
@       IN      TXT     "v=spf1 a mx ip4:$SERVER_IP ~all"
mail    IN      TXT     "v=spf1 a mx ip4:$SERVER_IP ~all"
EOF

systemctl restart bind9

# Configure DKIM
apt-get install opendkim opendkim-tools -y

cat <<EOF > /etc/opendkim/keytable
mail._domainkey.$DOMAIN $DOMAIN:mail:/etc/opendkim/keys/$DOMAIN/mail.private
EOF

mkdir /etc/opendkim/keys/$DOMAIN
opendkim-genkey -b 2048 -d $DOMAIN -D /etc/opendkim/keys/$DOMAIN -s mail -v

cat <<EOF >> /etc/opendkim.conf
KeyTable  /etc/opendkim/keytable
SigningTable  refile:/etc/opendkim/keytable
EOF

systemctl restart opendkim

# Install ClamAV and configure
apt-get install clamav clamav-daemon -y freshclam
echo "LocalSocket /var/run/clamav/clamd.ctl" >> /etc/clamav/clamd.conf
systemctl restart clamav-daemon

# Add DMARC record
cat <<EOF >> /var/named/spurs.gov.zone
_dmarc IN TXT "v=DMARC1; p=none; pct=100; rua=mailto:dmarcreports@$DOMAIN"
EOF

systemctl restart bind9

# Configure internal recursive DNS servers
apt-get install bind9-dnsutils -y
cat <<EOF > /etc/bind/named.conf.options
forwarders {
  $SERVER_IP;
  8.8.8.8;
  1.1.1.1;
};

allow-query { internal; };

recursion yes;
EOF

systemctl restart bind9

# Install mail utilities
apt-get install mailutils -y

# Configure Google Workspace MX records
cat <<EOF >> /var/named/spurs.gov.zone
@ MX 1 aspmx.l.google.com.
@ MX 5 alt1.aspmx.l.google.com.
@ MX 5 alt2.aspmx.l.google.com.
@ MX 10 alt3.aspmx.l.google.com.
@ MX 10 alt4.aspmx.l.google.com.
EOF

# Add DNS records for Google Workspace
cat <<EOF >> /var/bind/db.$DOMAIN
@       IN      MX      1       aspmx.l.google.com.
@       IN      MX      5       alt1.aspmx.l.google.com.
@       IN      MX      5       alt2.aspmx.l.google.com.
@       IN      MX      10      alt3.aspmx.l.google.com.
@       IN      MX      10      alt4.aspmx.l.google.com.
EOF

systemctl restart bind9

# Add TXT record for verification
cat <<EOF >> /var/named/spurs.gov.zone
@ TXT "$GOOGLE_VERIFICATION_CODE"
EOF

systemctl restart bind9

# Configure Postfix to relay outgoing mail via Google
postconf -e 'relayhost = [smtp.gmail.com]:587'
postconf -e 'smtp_sasl_auth_enable = yes'
postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
postconf -e 'smtp_sasl_security_options = noanonymous'
postconf -e 'smtp_use_tls = yes'
postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'

echo "[smtp.gmail.com]:587 USERNAME@gmail.com:PASSWORD" > /etc/postfix/sasl_passwd

postmap /etc/postfix/sasl_passwd
systemctl restart postfix

# Set up automated vulnerability scanning
apt-get install nmap nmap-vulners -y

cat <<EOF > /usr/local/bin/scan.sh
#!/bin/bash

# Vulnerability scan using Nmap

nmap -sV -oA \$(date +%Y%m%d%H%M%S)-scan $DOMAIN --script vulners
EOF

chmod +x /usr/local/bin/scan.sh

# Create cron job to run weekly scans
crontab -l > tempcron
echo "0 0 * * 0 /usr/local/bin/scan.sh" >> tempcron
crontab tempcron
rm tempcron

# Install and configure fail2ban for security
apt-get install fail2ban -y

# Copy default config
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Update configs
sed -i 's/bantime  = 600/bantime = 3600/' /etc/fail2ban/jail.local
sed -i 's/findtime = 600/findtime = 3600/' /etc/fail2ban/jail.local

# Set services to monitor
cat <<EOF >> /etc/fail2ban/jail.local
[ssh]
enabled = true
port = ssh
filter = sshd

[apache-auth]
enabled = true
EOF

systemctl restart fail2ban

# Set up backup
apt-get install duplicity -y

cat <<EOF > /root/backups.sh
#!/bin/bash
duplicity /etc file:///data/backups
duplicity /root file:///data/backups
duplicity /data file:///data/backups
EOF

chmod +x /root/backups.sh
echo "/bin/bash /root/backups.sh" | tee /etc/cron.daily/backups

# Setup complete
echo "Setup for $DOMAIN complete!"

# AWS CloudFormation Script

# Install AWS CLI
apt-get install -y awscli

# AWS CloudFormation JSON template to create the required infrastructure
cat <<EOF > /root/spurs-gov-cloudformation.json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "CloudFormation template to create infrastructure for spurs.gov",
  "Resources": {
    "SpursGovVPC": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsSupport": "true",
        "EnableDnsHostnames": "true",
        "Tags": [
          {
            "Key": "Name",
            "Value": "SpursGovVPC"
          }
        ]
      }
    },
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway",
      "Properties": {
        "Tags": [
          {
            "Key": "Name",
            "Value": "SpursGovIGW"
          }
        ]
      }
    },
    "AttachGateway": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": { "Ref": "SpursGovVPC" },
        "InternetGatewayId": { "Ref": "InternetGateway" }
      }
    },
    "PublicSubnet": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "VpcId": { "Ref": "SpursGovVPC" },
        "CidrBlock": "10.0.1.0/24",
        "AvailabilityZone": { "Fn::Select": [ "0", { "Fn::GetAZs": "" } ] },
        "Tags": [
          {
            "Key": "Name",
            "Value": "PublicSubnet"
          }
        ]
      }
    },
    "RouteTable": {
      "Type": "AWS::EC2::RouteTable",
      "Properties": {
        "VpcId": { "Ref": "SpursGovVPC" },
        "Tags": [
          {
            "Key": "Name",
            "Value": "PublicRouteTable"
          }
        ]
      }
    },
    "Route": {
      "Type": "AWS::EC2::Route",
      "Properties": {
        "RouteTableId": { "Ref": "RouteTable" },
        "DestinationCidrBlock": "0.0.0.0/0",
        "GatewayId": { "Ref": "InternetGateway" }
      }
    },
    "SubnetRouteTableAssociation": {
      "Type": "AWS::EC2::SubnetRouteTableAssociation",
      "Properties": {
        "SubnetId": { "Ref": "PublicSubnet" },
        "RouteTableId": { "Ref": "RouteTable" }
      }
    },
    "SecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "VpcId": { "Ref": "SpursGovVPC" },
        "GroupDescription": "Allow SSH and HTTP(S) traffic",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22",
            "CidrIp": "0.0.0.0/0"
          },
          {
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "0.0.0.0/0"
          },
          {
            "IpProtocol": "tcp",
            "FromPort": "443",
            "ToPort": "443",
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "SpursGovSecurityGroup"
          }
        ]
      }
    },
    "Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": "t2.micro",
        "SecurityGroupIds": [ { "Ref": "SecurityGroup" } ],
        "SubnetId": { "Ref": "PublicSubnet" },
        "ImageId": "ami-0c55b159cbfafe1f0",  # This is an Amazon Linux 2 AMI ID in us-east-1 region, update as necessary
        "KeyName": "YourKeyName",  # Make sure to replace with your key name
        "Tags": [
          {
            "Key": "Name",
            "Value": "SpursGovInstance"
          }
        ],
        "UserData": {
          "Fn::Base64": {
            "Fn::Join": [
              "",
              [
                "#!/bin/bash\n",
                "apt-get update -y\n",
                "apt-get upgrade -y\n",
                "apt-get install -y bind9 apache2 mysql-server php perl mutt exim4 postfix dovecot-imapd dovecot-pop3d ftp vsftpd sendmail iptables fail2ban ufw logwatch logrotate certbot nmap duplicity python3-pip awscli\n",
                "wget -N http://httpupdate.cpanel.net/latest\n",
                "sh latest\n",
                "hostnamectl set-hostname ", $DOMAIN, "\n",
                "echo '", $SERVER_IP, " ", $DOMAIN, "' >> /etc/hosts\n",
                "echo '", $SERVER_IPV6, " ", $DOMAIN, "' >> /etc/hosts\n",
                "echo 'root:changethis' | chpasswd\n",
                "echo 'HOSTNAME=", $DOMAIN, "' >> /etc/sysconfig/network\n",
                "ifdown eth0 && ifup eth0\n",
                "echo 'mysql-root-password=changethis' > /root/.my.cnf\n",
                "sed -i 's/PRIMARY_HOSTNAME=/PRIMARY_HOSTNAME=", $DOMAIN, "/' /etc/exim4/update-exim4.conf.conf\n",
                "sed -i 's/dc_other_hostnames='/dc_other_hostnames=", $DOMAIN, " '/etc/exim4/update-exim4.conf.conf\n",
                "sed -i 's/127.0.0.1/", $SERVER_IP, "/' /etc/exim4/exim.conf\n",
                "postconf -e 'myhostname = ", $DOMAIN, "'\n",
                "postconf -e 'mydomain = ", $DOMAIN, "'\n",
                "postconf -e 'myorigin = ", $DOMAIN, "'\n",
                "postconf -e 'inet_interfaces = all'\n",
                "postconf -e 'inet_protocols = all'\n",
                "cat <<EOF > /etc/bind/named.conf.local\n",
                "// Define zones\n",
                "zone '", $DOMAIN, "' IN {\n",
                "    type master;\n",
                "    file '/etc/bind/db.", $DOMAIN, "';\n",
                "};\n",
                "zone '", $SERVER_IP, ".in-addr.arpa' {\n",
                "    type master;\n",
                "    file '/etc/bind/db.", $SERVER_IP, "';\n",
                "};\n",
                "zone '", $SERVER_IPV6, ".in-addr.arpa' {\n",
                "    type master;\n",
                "    file '/etc/bind/db.", $SERVER_IPV6, "';\n",
                "};\n",
                "// Allow queries\n",
                "acl 'trusted' {\n",
                "    ", $SERVER_IP, ";\n",
                "    localhost;\n",
                "    localnets;\n",
                "};\n",
                "options {\n",
                "   directory '/var/cache/bind';\n",
                "   allow-query { trusted; };\n",
                "   recursion yes;\n",
                "   allow-recursion { trusted; };\n",
                "   dnssec-validation auto;\n",
                "   auth-nxdomain no;\n",
                "   listen-on { any; };\n",
                "};\n",
                "EOF\n",
                "cat <<EOF > /etc/bind/db.", $DOMAIN, "\n",
                "\$TTL    604800\n",
                                "@       IN      SOA     ", $DOMAIN, ". root.", $DOMAIN, ". (\n",
                "                              2         ; Serial\n",
                "                         604800         ; Refresh\n",
                "                          86400         ; Retry\n",
                "                        2419200         ; Expire\n",
                "                         604800 )       ; Negative Cache TTL\n",
                ";\n",
                "@       IN      NS      ns1.", $DOMAIN, ".\n",
                "@       IN      NS      ns2.", $DOMAIN, ".\n",
                "@       IN      A       ", $SERVER_IP, "\n",
                "@       IN      AAAA    ", $SERVER_IPV6, "\n",
                "www     IN      CNAME   @\n",
                "EOF\n",
                "cat <<EOF > /etc/bind/db.", $SERVER_IP, "\n",
                "\$TTL    604800\n",
                "@       IN      SOA     ", $DOMAIN, ". root.", $DOMAIN, ". (\n",
                "                              2         ; Serial\n",
                "                         604800         ; Refresh\n",
                "                          86400         ; Retry\n",
                "                        2419200         ; Expire\n",
                "                         604800 )       ; Negative Cache TTL\n",
                ";\n",
                "@       IN      PTR     ", $DOMAIN, ".\n",
                "EOF\n",
                "cat <<EOF > /etc/bind/db.", $SERVER_IPV6, "\n",
                "\$TTL    604800\n",
                "@       IN      SOA     ", $DOMAIN, ". root.", $DOMAIN, ". (\n",
                "                              2         ; Serial\n",
                "                         604800         ; Refresh\n",
                "                          86400         ; Retry\n",
                "                        2419200         ; Expire\n",
                "                         604800 )       ; Negative Cache TTL\n",
                ";\n",
                "@       IN      PTR     ", $DOMAIN, ".\n",
                "EOF\n",
                "systemctl restart bind9\n",
                "cat <<EOF > /etc/apache2/sites-available/", $DOMAIN, ".conf\n",
                "<VirtualHost *:80>\n",
                "  ServerName ", $DOMAIN, "\n",
                "  ServerAlias www.", $DOMAIN, "\n",
                "  DocumentRoot /var/www/", $DOMAIN, "/public_html\n",
                "  ErrorLog /var/www/", $DOMAIN, "/logs/error.log\n",
                "  CustomLog /var/www/", $DOMAIN, "/logs/access.log combined\n",
                "</VirtualHost>\n",
                "EOF\n",
                "a2ensite ", $DOMAIN, ".conf\n",
                "a2enmod ssl\n",
                "a2ensite default-ssl\n",
                "systemctl restart apache2\n",
                "certbot --apache -d ", $DOMAIN, "\n",
                "cat <<EOF > /etc/apache2/sites-available/redirect.conf\n",
                "<VirtualHost *:80>\n",
                "  ServerName ", $DOMAIN, "\n",
                "  Redirect '/' 'https://", $DOMAIN, "/'\n",
                "</VirtualHost>\n",
                "EOF\n",
                "a2ensite redirect.conf\n",
                "systemctl reload apache2\n",
                "ufw allow ssh\n",
                "ufw allow http\n",
                "ufw allow https\n",
                "ufw allow 21/tcp\n",
                "ufw allow 587/tcp\n",
                "ufw allow 465/tcp\n",
                "ufw allow 110/tcp\n",
                "ufw allow 143/tcp\n",
                "ufw allow pop3s\n",
                "ufw enable\n",
                "iptables -A INPUT -p tcp --dport 25 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 110 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 143 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 465 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 587 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 993 -j ACCEPT\n",
                "iptables -A INPUT -p udp --dport 53 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 53 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 80 -j ACCEPT\n",
                "iptables -A INPUT -p tcp --dport 443 -j ACCEPT\n",
                "iptables -A INPUT -i lo -j ACCEPT\n",
                "iptables -A OUTPUT -o lo -j ACCEPT\n",
                "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
                "iptables -A INPUT -p tcp --syn -j DROP\n",
                "service iptables save\n",
                "apt-get install spamassassin -y\n",
                "sed -i 's/RequiredHits 5/RequiredHits 3/' /etc/spamassassin/local.cf\n",
                "sed -i 's/rewrite_header Subject [SPAM]/rewrite_header Subject ***SPAM***/' /etc/spamassassin/local.cf\n",
                "apt-get install clamav clamav-daemon -y\n",
                "freshclam\n",
                "echo 'LocalSocket /var/run/clamav/clamd.ctl' >> /etc/clamav/clamd.conf\n",
                "systemctl restart clamav-daemon\n",
                "apt-get install postgrey -y\n",
                "sed -i 's/inet_interfaces = all/inet_interfaces = 127.0.0.1/g' /etc/postfix/main.cf\n",
                "sed -i 's/smtpd_client_restrictions =/smtpd_client_restrictions = check_policy_service inet:127.0.0.1:10023/g' /etc/postfix/main.cf\n",
                "systemctl restart postfix\n",
                "postconf -e 'relayhost = [smtp.gmail.com]:587'\n",
                "postconf -e 'smtp_sasl_auth_enable = yes'\n",
                "postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'\n",
                "postconf -e 'smtp_sasl_security_options = noanonymous'\n",
                "postconf -e 'smtp_use_tls = yes'\n",
                "postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'\n",
                "echo '[smtp.gmail.com]:587 you@gmail.com:password' > /etc/postfix/sasl_passwd\n",
                "postmap /etc/postfix/sasl_passwd\n",
                "systemctl reload postfix\n",
                "echo 'smarthost = smtp.gmail.com::587' >> /etc/exim4/exim4.conf.localmacros\n",
                "echo 'hide mysql_servers = 127.0.0.1/32' >> /etc/exim4/exim4.conf.localmacros\n",
                "cat <<EOF > /root/scripts/cloudflare_dns_setup.sh\n",
                "#!/bin/bash\n",
                "CLOUDFLARE_API_KEY='your_cloudflare_api_key'\n",
                "CLOUDFLARE_EMAIL='your_cloudflare_email'\n",
                "ZONE_ID='your_zone_id'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                "     --data '{\"type\":\"A\",\"name\":\"spurs.gov\",\"content\":\"$SERVER_IP\",\"ttl\":120,\"proxied\":false}'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                "     --data '{\"type\":\"AAAA\",\"name\":\"spurs.gov\",\"content\":\"$SERVER_IPV6\",\"ttl\":120,\"proxied\":false}'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                "     --data '{\"type\":\"MX\",\"name\":\"spurs.gov\",\"content\":\"aspmx.l.google.com\",\"priority\":1,\"ttl\":120,\"proxied\":false}'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                "     --data '{\"type\":\"MX\",\"name\":\"spurs.gov\",\"content\":\"alt1.aspmx.l.google.com\",\"priority\":5,\"ttl\":120,\"proxied\":false}'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                "     --data '{\"type\":\"MX\",\"name\":\"spurs.gov\",\"content\":\"alt2.aspmx.l.google.com\",\"priority\":5,\"ttl\":120,\"proxied\":false}'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                "     --data '{\"type\":\"MX\",\"name\":\"spurs.gov\",\"content\":\"alt3.aspmx.l.google.com\",\"priority\":10,\"ttl\":120,\"proxied\":false}'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                "     --data '{\"type\":\"MX\",\"name\":\"spurs.gov\",\"content\":\"alt4.aspmx.l.google.com\",\"priority\":10,\"ttl\":120,\"proxied\":false}'\n",
                "curl -X POST 'https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records' \\\n",
                "     -H 'X-Auth-Email: \$CLOUDFLARE_EMAIL' \\\n",
                "     -H 'X-Auth-Key: \$CLOUDFLARE_API_KEY' \\\n",
                "     -H 'Content-Type: application/json' \\\n",
                                "     --data '{\"type\":\"TXT\",\"name\":\"spurs.gov\",\"content\":\"$GOOGLE_VERIFICATION_CODE\",\"ttl\":120,\"proxied\":false}'\n",
                "EOF\n",
                "chmod +x /root/scripts/cloudflare_dns_setup.sh\n",
                "/root/scripts/cloudflare_dns_setup.sh\n",
                "apt-get install slapd ldap-utils -y\n",
                "dpkg-reconfigure slapd\n",
                "sed -i 's/#TLS_REQCERT.*/TLS_REQCERT demand/' /etc/ldap/ldap.conf\n",
                "echo 'TLS_CACERT /etc/ssl/certs/ca-certificates.crt' >> /etc/ldap/ldap.conf\n",
                "certbot certonly --standalone -d ", $DOMAIN, "\n",
                "a2enmod ssl\n",
                "a2ensite default-ssl\n",
                "cat <<EOF > /etc/apache2/sites-available/default-ssl.conf\n",
                "<IfModule mod_ssl.c>\n",
                "<VirtualHost *:443>\n",
                "  ServerName ", $DOMAIN, "\n",
                "  DocumentRoot /var/www/html\n",
                "  SSLEngine on\n",
                "  SSLCertificateFile /etc/letsencrypt/live/", $DOMAIN, "/fullchain.pem\n",
                "  SSLCertificateKeyFile /etc/letsencrypt/live/", $DOMAIN, "/privkey.pem\n",
                "</VirtualHost>\n",
                "</IfModule>\n",
                "EOF\n",
                "cat <<EOF > /etc/apache2/sites-available/redirect-http-to-https.conf\n",
                "<VirtualHost *:80>\n",
                "  ServerName ", $DOMAIN, "\n",
                "  Redirect '/' 'https://", $DOMAIN, "/'\n",
                "</VirtualHost>\n",
                "EOF\n",
                "a2ensite redirect-http-to-https.conf\n",
                "systemctl restart apache2\n",
                "ufw allow 53\n",
                "ufw allow 25/tcp\n",
                "ufw allow 587/tcp\n",
                "ufw allow 465/tcp\n",
                "ufw allow 110/tcp\n",
                "ufw allow 143/tcp\n",
                "ufw allow 443/tcp\n",
                "apt-get install wordpress -y\n",
                "mv /etc/wordpress/config-localhost.php /etc/wordpress/config-", $DOMAIN, ".php\n",
                "sed -i 's/localhost/", $DOMAIN, "/g' /etc/wordpress/config-", $DOMAIN, ".php\n",
                "chown -R www-data:www-data /var/www/html\n",
                "systemctl restart apache2\n",
                "systemctl restart mysql\n",
                "echo '0 0 * * * mysqldump -u root -p", $MYSQL_ROOT_PASSWORD, " companydb > /root/dbbackups/companydb-\\$(date +%Y%m%d).sql' >> /etc/crontab\n",
                "echo '0 0 * * 0 rm -f /root/dbbackups/*.sql.??*' >> /etc/crontab\n",
                "useradd -m user1\n",
                "useradd -m user2\n",
                "echo 'user1:password1' | chpasswd\n",
                "echo 'user2:password2' | chpasswd\n",
                "usermod -aG sudo user1\n",
                "ssh-copy-id user1@", $DOMAIN, "\n",
                "ssh-copy-id user2@", $DOMAIN, "\n",
                "sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config\n",
                "systemctl restart sshd\n",
                "apt-get install nagios4 -y\n",
                "htpasswd -c /etc/nagios4/htpasswd.users nagiosadmin\n",
                "cat <<EOF > /etc/nagios4/cgi.cfg\n",
                "authorized_for_system_information=nagiosadmin\n",
                "authorized_for_configuration_information=nagiosadmin\n",
                "authorized_for_system_commands=nagiosadmin\n",
                "authorized_for_all_services=nagiosadmin\n",
                "authorized_for_all_hosts=nagiosadmin\n",
                "authorized_for_all_service_commands=nagiosadmin\n",
                "authorized_for_all_host_commands=nagiosadmin\n",
                "EOF\n",
                "systemctl restart apache2\n",
                "systemctl restart nagios4\n",
                "apt-get install snort -y\n",
                "cat <<EOF > /etc/snort/snort.conf\n",
                "ipvar HOME_NET ", $DOMAIN, "/24\n",
                "var RULE_PATH /etc/snort/rules\n",
                "var SO_RULE_PATH /etc/snort/so_rules\n",
                "var PREPROC_RULE_PATH /etc/snort/preprocessors\n",
                "var WHITE_LIST_PATH /etc/snort/rules/whitelist\n",
                "var BLACK_LIST_PATH /etc/snort/rules/blacklist\n",
                "var DNS_SERVERS [", $SERVER_IP, "]\n",
                "var HTTP_PORTS 80\n",
                "var SHELLCODE_PORTS !80\n",
                "var ARP_SPOOF src & ARP_SPOOF dst\n",
                "EOF\n",
                "systemctl restart snort\n",
                "apt-get install logwatch -y\n",
                "echo 'Logwatch configured successfully!'\n",
                "apt-get install unattended-upgrades -y\n",
                "cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades\n",
                "Unattended-Upgrade::Allowed-Origins {\n",
                "    \"", $DOMAIN, "//./\\.\";\n",
                "};\n",
                "EOF\n",
                "dpkg-reconfigure --priority=low unattended-upgrades\n",
                "systemctl enable unattended-upgrades.service\n",
                "cat <<EOF >> /etc/logrotate.conf\n",
                "/var/log/apache2/*.log {\n",
                "  daily\n",
                "  missingok\n",
                "  rotate 7\n",
                "  compress\n",
                "  delaycompress\n",
                "  notifempty\n",
                "}\n",
                "/var/log/syslog {\n",
                "  daily\n",
                "  missingok\n",
                "  rotate 7\n",
                "  compress\n",
                "  delaycompress\n",
                "  notifempty\n",
                "}\n",
                "/var/log/auth.log {\n",
                "  daily\n",
                "  missingok\n",
                "  rotate 4\n",
                "  compress\n",
                "  delaycompress\n",
                "  notifempty\n",
                "}\n",
                "EOF\n",
                "(\n",
                "    echo o; echo n; echo p; echo 1; echo; echo; echo w;\n",
                ") | fdisk /dev/vda\n",
                "mkfs.ext4 /dev/vda1\n",
                "echo '/dev/vda1  /data ext4    defaults    1  1' >> /etc/fstab\n",
                "mount -a\n",
                "chmod 775 /data\n",
                "mkdir /data/logs\n",
                "chmod 775 /data/logs\n",
                "mv /var/log/* /data/logs/\n",
                "ln -s /data/logs/* /var/log/\n",
                "fallocate -l 2G /data/swapfile\n",
                "chmod 600 /data/swapfile\n",
                "mkswap /data/swapfile\n",
                "swapon /data/swapfile\n",
                "echo '/data/swapfile none swap sw 0 0' >> /etc/fstab\n",
                "echo 'Server configuration complete!'\n",
                "apt-get install postfix-policyd-spf-python -y\n",
                "echo 'policy_time_limit = 3600' >> /etc/postfix-policyd-spf-python/policyd-spf.conf\n",
                "postconf -e 'smtpd_client_restrictions = check_policy_service inet:127.0.0.1:10023'\n",
                "systemctl restart postfix\n",
                "cat <<EOF >> /var/named/spurs.gov.zone\n",
                "@       IN      TXT     'v=spf1 a mx ip4:", $SERVER_IP, " ~all'\n",
                "mail    IN      TXT     'v=spf1 a mx ip4:", $SERVER_IP, " ~all'\n",
                "EOF\n",
                "systemctl restart bind9\n",
                "apt-get install opendkim opendkim-tools -y\n",
                "cat <<EOF > /etc/opendkim/keytable\n",
                "mail._domainkey.", $DOMAIN, " ", $DOMAIN, ":mail:/etc/opendkim/keys/", $DOMAIN, "/mail.private\n",
                "EOF\n",
                "mkdir /etc/opendkim/keys/", $DOMAIN, "\n",
                "opendkim-genkey -b 2048 -d ", $DOMAIN, " -D /etc/opendkim/keys/", $DOMAIN, " -s mail -v\n",
                "cat <<EOF >> /etc/opendkim.conf\n",
                "KeyTable  /etc/opendkim/keytable\n",
                "SigningTable  refile:/etc/opendkim/keytable\n",
                                "EOF\n",
                "systemctl restart opendkim\n",
                "apt-get install clamav clamav-daemon -y\n",
                "freshclam\n",
                "echo 'LocalSocket /var/run/clamav/clamd.ctl' >> /etc/clamav/clamd.conf\n",
                "systemctl restart clamav-daemon\n",
                "cat <<EOF >> /var/named/spurs.gov.zone\n",
                "_dmarc IN TXT 'v=DMARC1; p=none; pct=100; rua=mailto:dmarcreports@", $DOMAIN, "'\n",
                "EOF\n",
                "systemctl restart bind9\n",
                "apt-get install bind9-dnsutils -y\n",
                "cat <<EOF > /etc/bind/named.conf.options\n",
                "forwarders {\n",
                "  ", $SERVER_IP, ";\n",
                "  8.8.8.8;\n",
                "  1.1.1.1;\n",
                "};\n",
                "allow-query { internal; };\n",
                "recursion yes;\n",
                "EOF\n",
                "systemctl restart bind9\n",
                "apt-get install mailutils -y\n",
                "cat <<EOF >> /var/named/spurs.gov.zone\n",
                "@ MX 1 aspmx.l.google.com.\n",
                "@ MX 5 alt1.aspmx.l.google.com.\n",
                "@ MX 5 alt2.aspmx.l.google.com.\n",
                "@ MX 10 alt3.aspmx.l.google.com.\n",
                "@ MX 10 alt4.aspmx.l.google.com.\n",
                "EOF\n",
                "cat <<EOF >> /var/bind/db.", $DOMAIN, "\n",
                "@       IN      MX      1       aspmx.l.google.com.\n",
                "@       IN      MX      5       alt1.aspmx.l.google.com.\n",
                "@       IN      MX      5       alt2.aspmx.l.google.com.\n",
                "@       IN      MX      10      alt3.aspmx.l.google.com.\n",
                "@       IN      MX      10      alt4.aspmx.l.google.com.\n",
                "EOF\n",
                "systemctl restart bind9\n",
                "cat <<EOF >> /var/named/spurs.gov.zone\n",
                "@ TXT '", $GOOGLE_VERIFICATION_CODE, "'\n",
                "EOF\n",
                "systemctl restart bind9\n",
                "postconf -e 'relayhost = [smtp.gmail.com]:587'\n",
                "postconf -e 'smtp_sasl_auth_enable = yes'\n",
                "postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'\n",
                "postconf -e 'smtp_sasl_security_options = noanonymous'\n",
                "postconf -e 'smtp_use_tls = yes'\n",
                "postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'\n",
                "echo '[smtp.gmail.com]:587 USERNAME@gmail.com:PASSWORD' > /etc/postfix/sasl_passwd\n",
                "postmap /etc/postfix/sasl_passwd\n",
                "systemctl restart postfix\n",
                "apt-get install nmap nmap-vulners -y\n",
                "cat <<EOF > /usr/local/bin/scan.sh\n",
                "#!/bin/bash\n",
                "nmap -sV -oA \\$(date +%Y%m%d%H%M%S)-scan ", $DOMAIN, " --script vulners\n",
                "EOF\n",
                "chmod +x /usr/local/bin/scan.sh\n",
                "crontab -l > tempcron\n",
                "echo '0 0 * * 0 /usr/local/bin/scan.sh' >> tempcron\n",
                "crontab tempcron\n",
                "rm tempcron\n",
                "apt-get install fail2ban -y\n",
                "cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local\n",
                "sed -i 's/bantime  = 600/bantime = 3600/' /etc/fail2ban/jail.local\n",
                "sed -i 's/findtime = 600/findtime = 3600/' /etc/fail2ban/jail.local\n",
                "cat <<EOF >> /etc/fail2ban/jail.local\n",
                "[ssh]\n",
                "enabled = true\n",
                "port = ssh\n",
                "filter = sshd\n",
                "[apache-auth]\n",
                "enabled = true\n",
                "EOF\n",
                "systemctl restart fail2ban\n",
                "apt-get install duplicity -y\n",
                "cat <<EOF > /root/backups.sh\n",
                "#!/bin/bash\n",
                "duplicity /etc file:///data/backups\n",
                "duplicity /root file:///data/backups\n",
                "duplicity /data file:///data/backups\n",
                "EOF\n",
                "chmod +x /root/backups.sh\n",
                "echo '/bin/bash /root/backups.sh' | tee /etc/cron.daily/backups\n",
                "echo 'Setup for ", $DOMAIN, " complete!'\n"
              ]
            ]
          }
        }
      }
    }
  }
}
EOF

# Deploy the CloudFormation stack
aws cloudformation create-stack --stack-name SpursGovStack --template-body file:///root/spurs-gov-cloudformation.json --capabilities CAPABILITY_NAMED_IAM

# Print stack details
aws cloudformation describe-stacks --stack-name SpursGovStack

