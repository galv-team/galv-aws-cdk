# 🚀 Galv Backend Infrastructure (AWS CDK)

This repository defines the infrastructure for the Galv backend using AWS CDK (Python). It provisions everything needed to run the Django application in production, including compute, storage, database, email, background tasks, and static frontend hosting.

---

## ✅ Quick Start: How to Deploy

1. **Ensure required artifacts are available (optional):**

   - The specified version of the backend image should be available on GitHub Container Registry (GHCR)
   - The specified version of the frontend should be tagged in the GitHub repository

   By default, both frontend and backend will use the `:latest` tag, which is expected to be available in typical deployments.

2. **Bootstrap the CDK (once per account/region):**

```bash
cdk bootstrap
```

3. **Configure your deployment in `cdk.json` (see below)**

4. **Deploy the infrastructure:**

```bash
cdk deploy
```

The deployment will:

- Provision a Postgres database
- Deploy the backend service behind an Application Load Balancer (ALB)
- Create scheduled and on-demand ECS tasks
- Run initial setup (`migrate`, `create_superuser`, `loaddata`)
- Schedule validation polling every 5 minutes
- Build and deploy the static frontend to S3 + CloudFront

Everything will be tagged with `project-name` = the project name for easy identification.

---

## ⚙️ Configuration: `cdk.json` Context Keys

Configure your environment by editing `cdk.json`. The following table describes the key options:

| Key                       | Description                                                                                           |
|---------------------------|-------------------------------------------------------------------------------------------------------|
| `name`                    | A short name used to prefix resources                                                                 |
| `backendVersion`          | Tag for backend Docker image (e.g. from GHCR)                                                         |
| `frontendVersion`         | Tag for frontend Docker image (e.g. from GHCR)                                                        |
| `projectNameTag`          | Used for tagging and grouping resources                                                               |
| `isProduction`            | Controls retention policies and protections, debugging, ECS exec                                      |
| `removalProtection`       | Overrides retention policies and protections (e.g., deletion protection)                              |
| `mailFromUser`            | Local part of the default email sender address                                                        |
| `mailFromDomain`          | Domain for the default email sender address                                                           |
| `frontendEnvironment`     | Key-value pairs of environment variables to pass to the frontend container                            |
| `backendEnvironment`      | Key-value pairs of environment variables to pass to the backend container                             |
| `frontendSecretsName`     | Name of the AWS Secrets Manager entry for frontend secrets                                            |
| `frontendSecretsKeys`     | List of secret keys to inject into the frontend container                                             |
| `backendSecretsName`      | Name of the AWS Secrets Manager entry for backend secrets                                             |
| `backendSecretsKeys`      | List of secret keys to inject into the backend container                                              |
| `monitorIntervalMinutes`  | How often to run the validation monitor task (0 disables it)                                          |
| `frontendSubdomain`       | Subdomain for the frontend (e.g., `app`)                                                              |
| `backendSubdomain`        | Subdomain for the backend (e.g., `api`)                                                               |
| `domainName`              | Domain name for the application (e.g., `example.com`)                                                 |
| `isRoute53Domain`         | Whether the domain is managed by Route 53 (true/false)                                                |
| `enableContainerInsights` | Whether to enable CloudWatch Container Insights for ECS tasks (true/false). Defaults to isProduction. |
| `certificateArn`          | ARN of an existing ACM certificate when the domain is not in Route 53                                 |
| `smtpSecretName`          | Name of the AWS Secrets Manager entry for SMTP credentials. Defaults to `projectNameTag`-smtp         |

Example `cdk.json`:

```json
{
  "app": "python3 app.py",
  "context": {
    "name": "galv",
    "mailFromDomain": "mail.example.com",
    "mailFromUser": "galv-no-reply",
    "projectNameTag": "galv",
    "backendVersion": "latest",
    "isProduction": true,
    "frontendEnvironment": {},
    "backendEnvironment": {
      "DJANGO_SUPERUSER_USERNAME": "admin",
      "DJANGO_LOG_LEVEL": "INFO",
      "DJANGO_USER_ACTIVATION_OVERRIDE_ADDRESSES": "",
      "DJANGO_USER_ACTIVATION_TOKEN_EXPIRY_S": ""
    },
    "frontendSecretsName": "galv-frontend-secrets",
    "frontendSecretsKeys": [],
    "backendSecretsName": "galv-backend-secrets",
    "backendSecretsKeys": [],
    "monitorIntervalMinutes": 5
  }
}
```

### 🔐 Certificates, WAF & Logs

The stacks need TLS certificates for the frontend and backend domains. When
`isRoute53Domain` is `true` the certificates are created automatically and
validated using Route 53 DNS records. If the domain is external you must supply
an existing certificate ARN via the `certificateArn` context key. See
`get_aws_custom_cert_instructions` for the manual ACM steps and example
`--context certificateArn=arn:aws:acm:us-east-1:<account-id>:certificate/<uuid>`.

A WAFv2 WebACL is attached to each load balancer and a dedicated S3 log bucket
is created for ALB, flow log and WAF logs.


---

## 🧱 Infrastructure Overview

### 💡 Core Services

| Resource           | Purpose                                |
|--------------------|----------------------------------------|
| ECS Fargate        | Hosts Django app (via gunicorn)        |
| ALB                | Routes web traffic to backend          |
| RDS (Postgres)     | Application database                   |
| S3                 | Media + static file storage + frontend |
| CloudFront         | Delivers the frontend globally         |
| Secrets Manager    | Stores DB, SMTP, and app secrets       |
| SES (SMTP)         | Sends email (via IAM-auth SMTP)        |

### ♻️ ECS Tasks

| Task                | Purpose                                 | Trigger                     |
|---------------------|------------------------------------------|-----------------------------|
| `setup_db.sh`       | Runs migrations, creates superuser, loads fixtures | Once at deploy         |
| `validation_monitor`| Scans and validates datasets             | Scheduled (default: 5 min)  |
| `check_status`      | Verifies DB/S3/SMTP/Django config        | Optional post-deploy task   |

---

## 🛠️ Running and Debugging

### ✅ Health Check

The Application Load Balancer (ALB) performs health checks at `/health/`. Ensure your Django app exposes this endpoint and it returns `200 OK` to signal the container is healthy.

### 🧰 On-demand checks

Run this ECS task to verify services are properly connected:

```bash
python manage.py check_status
```

Supports `--json` for CI-friendly output. Checks include:
- Django config/system integrity
- Database connection
- S3 connection (if enabled)
- SMTP configuration and connectivity

### 📦 Logs

All ECS tasks log to CloudWatch. Log groups are named by task (e.g., `check-status`, `validation-monitor`). Use the AWS Console or CLI to view logs.

---

## 📄 AWS Glossary

| Full Name                      | Short Name       | Description                                                                 |
|--------------------------------|------------------|-----------------------------------------------------------------------------|
| Elastic Container Service      | ECS              | Orchestrates container deployment and scaling                              |
| Fargate                        | -                | Serverless compute engine for ECS tasks and services                        |
| Application Load Balancer     | ALB              | Routes web traffic to ECS services with health checks and load balancing    |
| Relational Database Service    | RDS              | Manages the Postgres database for the backend                               |
| Simple Storage Service         | S3               | Stores media files, static files, and frontend assets                       |
| CloudFront                     | -                | Global CDN for serving frontend assets from S3                              |
| Secrets Manager                | -                | Securely stores credentials and sensitive data                              |
| Simple Email Service           | SES              | Sends application emails via SMTP with IAM-auth                             |
| GitHub Container Registry      | GHCR             | Stores and serves the Docker image used by the backend                      |

---

## Development

Development happens on the `develop` branch. 
Please target pull requests to `develop` for review.

Once changes are approved, they will be merged into `main`. 
Releases are tagged from `main`.

Please ensure your changes are well-tested and documented before submitting a PR.

--- 

## Deploying with GitHub Actions

Galv repositories can use GitHub Actions to automate deployments.
These actions will invoke this CDK to deploy the infrastructure.
Ensure your repository has the necessary secrets configured for deployment.

The IAM role is written to be simple and robust rather than minimizing permissions.
This means that it has broader permissions than necessary, so its use should be limited and carefully monitored.

To set up the relevant IAM roles and identities, you'll need to:
1. Create an IAM role with: 
   - Trusted entity: `Web Identity`
   - Web identity provider: `token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`
   - GitHub organization: `galv-team`
   - Permissions from `permissions.json`
2. Create an IAM user 
