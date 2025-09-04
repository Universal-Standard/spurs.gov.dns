# spurs.gov.dns

This project contains a CloudFormation template and a setup script to deploy a secure and scalable web infrastructure on AWS for the `spurs.gov` domain.

## Features

- **Automated Infrastructure Deployment:** Uses CloudFormation to automate the creation of all necessary AWS resources, including a VPC, subnets, security groups, and an EC2 instance.
- **Secure by Default:** The infrastructure is deployed with security best practices in mind, including:
    - A restrictive firewall that only allows traffic from trusted sources.
    - An IAM role for the EC2 instance to securely access other AWS services.
    - Security headers in the Apache configuration to protect against common web vulnerabilities.
- **Scalable and Flexible:** The CloudFormation template is designed to be scalable and flexible, with parameters that allow you to customize the deployment to your specific needs.

## Prerequisites

Before you can deploy the infrastructure, you need to have the following:

- An AWS account.
- The AWS CLI installed and configured.
- A domain name registered with a domain registrar.
- A Cloudflare account.

## Deployment

To deploy the infrastructure, follow these steps:

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
