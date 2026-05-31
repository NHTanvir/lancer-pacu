# lancer-pacu

Rust clone of `pacu`. Part of the Lancer ecosystem — a complete 2026 AI-era bug bounty toolkit.

## Safety notice -- --armed flag

**All state-mutating AWS API calls are disabled by default.**

lancer-pacu starts in `--dry-run` mode. Every module that can modify AWS
resources (create users, attach policies, modify security groups, etc.) checks
`ctx.armed` before executing any write call. In dry-run mode the module prints
what it *would* do and exits safely.

To enable write operations you must explicitly pass `--armed` at startup:

```
lancer-pacu --armed
```

This generates real AWS CloudTrail events. **Only use --armed with explicit
written authorization from the account owner.**

## Build

### Windows
Double-click `build.bat` or run from cmd:
```
build.bat
```
Output: `build\lancer-pacu.exe`

For a packaged dist build:
```
build-windows.bat
```
Output: `dist\lancer-pacu-windows-x86_64\bin\lancer-pacu.exe`

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/lancer-pacu`

### Requirements
- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Module list (27 modules)

### ENUM

| Module | Description |
|--------|-------------|
| `aws_enum_account` | Enumerate account metadata (account ID, aliases, org membership). |
| `iam_enum_users_roles_policies_groups` | Enumerate all IAM users, roles, policies, and groups. |
| `iam_get_credential_report` | Generate and download the IAM credential report. |
| `iam_enum_permissions` | Enumerate effective permissions for the current principal. |
| `ec2_enum` | Enumerate EC2 instances, security groups, AMIs, and VPCs. |
| `ebs_enum_volumes_snapshots` | Enumerate EBS volumes and snapshots (with public snapshot detection). |
| `lambda_enum` | Enumerate Lambda functions, layers, and attached IAM roles. |
| `detection_enum_services` | Enumerate detection services: CloudTrail, GuardDuty, Config, SecurityHub. |
| `vpc_enum_lateral_movement` | Enumerate VPC topology, peering, and Transit Gateway for lateral movement paths. |

### ESCALATE

| Module | Description |
|--------|-------------|
| `iam_privesc_scan` | IAM privilege escalation path finder (25 checks). --scan-only to report; --exploit with --armed to execute. |

### EXPLOIT

| Module | Description |
|--------|-------------|
| `ec2_backdoor_ec2_sec_groups` | Inject permissive inbound rules into EC2 security groups. Requires --armed + --exploit. |
| `organizations_assume_role` | Attempt to assume a role in every account in an AWS Organization. Requires --armed + --exploit. |

### PERSIST

| Module | Description |
|--------|-------------|
| `lambda_backdoor_new_roles` | Attach admin-level IAM policies to Lambda execution roles. Requires --armed + --exploit. |
| `lambda_backdoor_new_sec_groups` | Inject attacker-controlled security groups into a Lambda VPC config. Requires --armed + --exploit. |
| `lambda_backdoor_new_users` | Plant a backdoor Lambda that creates a new IAM admin user when invoked. Requires --armed + --exploit. |
| `iam_backdoor_users_keys` | Create a hidden access key on a target IAM user for persistent access. Requires --armed + --exploit. |
| `iam_backdoor_assume_role` | Modify a role trust policy to allow an attacker-controlled principal to assume it. Requires --armed + --exploit. |

### EVADE

| Module | Description |
|--------|-------------|
| `detection_disruption` | Disable/disrupt detection services (CloudTrail, GuardDuty, Config). Requires --armed + --exploit. |
| `guardduty_whitelist_ip` | Add an IP to the GuardDuty trusted IP list (suppresses findings). Requires --armed + --exploit. |
| `cloudtrail_csv_injection` | Inject CSV formula payloads into CloudTrail tags for log-analysis tool exploitation. |

### EXFIL

| Module | Description |
|--------|-------------|
| `ebs_download_snapshots` | List (dry-run) or create/attach an EBS volume from a snapshot (--armed). |
| `s3_download_bucket` | List (dry-run) or download (--armed) objects from an S3 bucket. |
| `cloudtrail_download_event_history` | Download CloudTrail event history to a local JSON file. |
| `sns_subscribe` | Subscribe an attacker-controlled endpoint to SNS topics for data exfiltration. Requires --armed + --exploit. |
| `rds_explore_snapshots` | Enumerate RDS snapshots and optionally restore them. --exploit + --armed to restore. |
| `secrets_enum` | Enumerate/retrieve Secrets Manager secrets. --scan-only is safe; --secret-name/--all require --armed. |
| `systemsmanager_download_parameters` | Describe or download SSM Parameter Store values. --with-decryption requires --armed. |

## Example session workflow

```
# Start in dry-run (safe) mode
$ lancer-pacu

# Create a session and store credentials
Pacu (lancer) > new_session engagement-2026
Pacu (lancer) > set_keys AKIA... wJalr...
Pacu (lancer) > whoami

# Enumerate permissions
Pacu (lancer) > run iam_enum_permissions
Pacu (lancer) > run iam_privesc_scan

# If on an EC2 instance, fetch credentials from IMDS
Pacu (lancer) > set_keys_imds

# Configure a SOCKS5 proxy (storage layer -- SDK routing deferred)
Pacu (lancer) > set_proxy socks5://127.0.0.1:1080
Pacu (lancer) > proxy

# Export the current session for later
Pacu (lancer) > export my-session-backup.json

# Import a previously exported session
Pacu (lancer) > import my-session-backup.json

# Exit
Pacu (lancer) > exit
```

To run write operations, restart with `--armed`:

```
$ lancer-pacu --armed
Pacu (lancer) > run iam_privesc_scan --exploit
Pacu (lancer) > run ebs_download_snapshots --snapshot-id snap-0abc123
```

## Status

172+ tests passing. 27 modules complete.
