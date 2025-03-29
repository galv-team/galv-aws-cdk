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

---

## ⚙️ Configuration: `cdk.json` Context Keys

Configure your environment by editing `cdk.json`. The following table describes the key options:

| Key                      | Description                                                               |
| ------------------------ | ------------------------------------------------------------------------- |
| `name`                   | A short name used to prefix resources                                     |
| `backendVersion`         | Tag for backend Docker image (e.g. from GHCR)                             |
| `projectNameTag`         | Used for tagging and grouping resources                                   |
| `isProduction`           | Controls retention policies and protections (e.g., deletion protection)   |
| `mailFromUser`           | Local part of the default email sender address                            |
| `mailFromDomain`         | Domain for the default email sender address                               |
| `frontendEnvironment`    | Key-value pairs of environment variables to pass to the frontend container |
| `backendEnvironment`     | Key-value pairs of environment variables to pass to the backend container |
| `frontendSecretsName`    | Name of the AWS Secrets Manager entry for frontend secrets                |
| `frontendSecretsKeys`    | List of secret keys to inject into the frontend container                 |
| `backendSecretsName`     | Name of the AWS Secrets Manager entry for backend secrets                 |
| `backendSecretsKeys`     | List of secret keys to inject into the backend container                  |
| `monitorIntervalMinutes` | How often to run the validation monitor task (0 disables it)              |

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

