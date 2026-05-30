# RESEARCH DOSSIER: Pacu

> Part of the Lancer ecosystem. A Rust clone of Rhino Security Labs' Pacu — AWS post-exploitation framework. Build with Claude Code.
> Upstream: github.com/RhinoSecurityLabs/pacu (Python, ~75 modules, BSD-3). Read-only is Prowler; Pacu acts.
>
> ⚠️ AUTHORIZED USE ONLY. Default `--dry-run`; require explicit `--armed` to mutate state.

## Feature Parity Mandate

**`lancer-pacu` MUST ship with 100% feature parity to the upstream `pacu` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `pacu --help` (and the long-form man page / docs) must work in `lancer-pacu --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-pacu` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-pacu --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Pacu is **the** AWS post-exploitation framework from Rhino Security Labs. Where Prowler audits, Pacu **acts**. Once you have a set of AWS keys, Pacu lets you enumerate the account, identify privilege escalation paths, escalate, persist via backdoors (IAM, Lambda CloudWatch triggers, security groups), pivot, exfiltrate (S3, EBS snapshots, secrets), and impair detection. **~92 modules across 8 categories (v1.7.0, March 2026 — up from ~75 in v1.6)** including the `aws__enum_account`, `aws__enum_spend`, `ds__enum`, `elasticbeanstalk__enum`, `mq__enum`, `eks__collect_tokens`, `guardduty__list_accounts`, `guardduty__list_findings` additions. Interactive CLI (Metasploit-style) backed by a SQLite session DB that caches enumerated data so multi-module workflows don't re-call APIs. Also features a built-in AWS CLI passthrough: typing `aws <cli_command>` at the prompt executes AWS CLI commands using the active session credentials, without leaving the REPL.

## Internal architecture (with file refs)

```
pacu/
  __main__.py            # CLI entrypoint (`pacu` command)
  main.py                # Main class with the REPL loop
  core/                  # Session, DB, color, lib
    lib.py               # shared helpers (key_info, boto3 client factory)
  modules/               # all attack modules
    <category>__<name>/
      main.py            # module impl
      <name>.html        # optional template
  settings.py
  models.py              # SQLAlchemy models: PacuSession, AWSKey
```

**Session DB** (SQLite via SQLAlchemy):
- `pacu_session(name, key_alias, access_key_id, secret_access_key, session_token, region, vpcs, subnets, route_tables, ec2_instances, ec2_security_groups, ec2_amis, ec2_volumes, ec2_snapshots, s3_buckets, lambda_functions, iam_users, iam_roles, iam_groups, iam_policies, ...)` — every enumerated resource is a JSON-serialized column.
- `aws_key(...)` linked to session for multi-key swapping.
- `proxy_settings` for SOCKS pivoting.

The DB lives in `~/.local/share/pacu/sessions.sqlite` (or `%APPDATA%\pacu\` on Windows). When `iam__enum_users_roles_policies_groups` runs, it serializes results into `session.iam_users` so `iam__privesc_scan` can read without re-calling IAM.

**Module discovery:** at REPL start, Pacu walks `pacu/modules/` for any directory containing `main.py` and imports it. Each module exposes a `module_info` dict:
```python
module_info = {
    'name': 'iam__privesc_scan',
    'author': 'Spencer Gietzen of Rhino Security Labs',
    'category': 'ESCALATE',
    'one_liner': 'An IAM privilege escalation path finder and abuser.',
    'description': '...',
    'services': ['IAM'],
    'prerequisite_modules': ['iam__enum_permissions'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--offline', '--folder', '--scan-only', ...],
}
def main(args, pacu_main): ...
def summary(data, pacu_main): ...
```
The REPL's `list` / `search` / `run <module> --args` commands are driven by this catalog.

**Plugin/module API contract:**
- `pacu_main.get_active_session()` → session ORM object
- `pacu_main.get_boto3_client(service, region=None)` → boto3 client with session creds (handles `region=None` for global services automatically)
- `pacu_main.print(text)` → tee to stdout + session log
- `pacu_main.input(prompt)` → REPL-aware input
- `pacu_main.fetch_data(['IAM', 'Users'], 'iam__enum_users_roles_policies_groups', ...)` → enforces prerequisite, runs if missing
- `pacu_main.update_<resource>(...)` → writes back to DB

## Complete module catalog (~75 modules, by category)

**RECON_UNAUTH (3)** — `ebs__enum_snapshots_unauth`, `iam__enum_roles`, `iam__enum_users`

**ENUM (35+)** — `acm__enum`, `apigateway__enum`, `aws__enum_account`, `aws__enum_spend`, `cloudformation__download_data`, `codebuild__enum`, `cognito__enum`, `ds__enum`, `dynamodb__enum`, `ebs__enum_volumes_snapshots`, `ec2__check_termination_protection`, `ec2__download_userdata`, `ec2__enum`, `ecr__enum`, `ecs__enum`, `ecs__enum_task_def`, `eks__enum`, `elasticbeanstalk__enum`, `elb__enum_logging`, `glue__enum`, `iam__bruteforce_permissions`, `iam__decode_accesskey_id`, `iam__detect_honeytokens`, `iam__enum_action_query`, `iam__enum_permissions`, `iam__enum_users_roles_policies_groups`, `iam__get_credential_report`, `inspector__get_reports`, `lambda__enum`, `lightsail__enum`, `mq__enum`, `organizations__enum`, `rds__enum`, `rds__enum_snapshots`, `route53__enum`, `secrets__enum`, `sns__enum`, `systemsmanager__download_parameters`, `transfer_family__enum`, `waf__enum`

**ESCALATE (2)** — `iam__privesc_scan` (the marquee module; runs the 21 Rhino privesc checks), `cfn__resource_injection`

**EXPLOIT (9)** — `api_gateway__create_api_keys`, `cognito__attack`, `ebs__explore_snapshots`, `ec2__startup_shell_script`, `ecs__backdoor_task_def`, `lightsail__download_ssh_keys`, `lightsail__generate_ssh_keys`, `lightsail__generate_temp_access`, `systemsmanager__rce_ec2`

**PERSIST (7)** — `ec2__backdoor_ec2_sec_groups`, `iam__backdoor_assume_role`, `iam__backdoor_users_keys`, `iam__backdoor_users_password`, `lambda__backdoor_new_roles`, `lambda__backdoor_new_sec_groups`, `lambda__backdoor_new_users`

**EVADE (7)** — `cloudtrail__download_event_history`, `cloudwatch__download_logs`, `detection__disruption`, `detection__enum_services`, `elb__enum_logging`, `guardduty__whitelist_ip`, `waf__enum`

**Additional GuardDuty / EKS (added v1.6.1+):** `guardduty__list_accounts`, `guardduty__list_findings`, `eks__collect_tokens` (extracts EKS service-account JWT tokens for cluster pivoting)

**EXFIL (3)** — `ebs__download_snapshots`, `rds__explore_snapshots`, `s3__download_bucket`

**LATERAL_MOVE (4)** — `cloudtrail__csv_injection`, `organizations__assume_role`, `sns__subscribe`, `vpc__enum_lateral_movement`

## Complete CLI flag and REPL command reference (parity target)

**CLI flags (non-REPL invocation, `pacu --flag`):**

| Flag | Purpose |
|------|---------|
| `--session <name>` | Specify session to load |
| `--activate-session` | Auto-activate the named session (no REPL prompt) |
| `--new-session <name>` | Create new session and enter it |
| `--list-modules` | List every module (alpha by category) and exit |
| `--module-name <name>` | Specify the target module for `--exec` |
| `--module-info` | Print full description of a module and exit |
| `--module-args="<arg1> <val1> <arg2> <val2>"` | Pass arguments to the module |
| `--exec` | Execute the specified module (must combine with `--module-name`) |
| `--data <service|all>` | Dump session DB data for a service (or all) and exit |
| `--set-keys` | Configure AWS credentials non-interactively (alias/id/key/token) |
| `--import-keys <profile>` | Import keys from named AWS CLI profile |
| `--set-regions <region1 region2 | all>` | Configure target regions for the session |
| `--whoami` | Show active credentials' principal info (STS GetCallerIdentity) |
| `--pacu-help` | Show full Pacu help and exit |
| `--version` | Print version and exit |
| `-q`, `--quiet` | Suppress banner |

**REPL commands (inside the interactive shell):**

| Command | Purpose |
|---------|---------|
| `ls` / `list` | List modules available for configured regions |
| `search <term>` | Search modules whose name/description contains `term` |
| `help <module>` | Module help (description + arguments) |
| `run <module>` / `exec <module>` | Execute module with default args |
| `run <module> --regions r1,r2` | Run module against a region subset |
| `whoami` | Show active key alias, account ID, ARN, permissions count |
| `data` / `data <service>` | Dump cached session data (whole DB or one service) |
| `services` | List services with cached data in the session |
| `regions` | Print full list of AWS regions |
| `set_regions <r1> <r2>` | Configure target regions |
| `update_regions` | Auto-update the bundled region list via pip3/pip |
| `set_keys` | Create a new keyset in the session and make it active |
| `swap_keys` | Switch between keysets stored in the session |
| `import_keys <profile>` | Import a single AWS CLI profile from `~/.aws/credentials` |
| `import_keys --all` | Import every profile from `~/.aws/credentials` |
| `aws <cli command>` | Run an AWS CLI command using current session credentials (passthrough) |
| `aliases` | Show available command aliases (added v1.6.1) |
| `history` | Show command history for the current REPL session (added v1.6.1) |
| `exit` / `quit` / `Ctrl+C` | Quit Pacu |

**Install matrix (parity vehicles):**

| Method | Command | Notes |
|--------|---------|-------|
| pip3 | `pip3 install -U pacu && pacu` | Default; Python 3.7+ |
| pipx | `pipx install git+https://github.com/RhinoSecurityLabs/pacu.git` | Preferred for Kali Linux |
| Docker | `docker run -it rhinosecuritylabs/pacu:latest` | Image rebuilt per release |
| Docker + AWS creds mount | `docker run -it -v ~/.aws:/root/.aws rhinosecuritylabs/pacu:latest` | Reuse host AWS CLI profiles |
| Docker shell | `docker run -it --entrypoint /bin/sh rhinosecuritylabs/pacu:latest` | For debugging the container |

**Session DB / data directory locations:**

- Linux/macOS (pip install): `~/.local/share/pacu/<session>/` (DB at `sessions.sqlite`, command logs at `cmd_log.txt`, error logs at `error_log.txt`).
- Windows: `%APPDATA%\pacu\<session>\`.
- Legacy (pre-1.5): `./sessions/<session>/` relative to cwd.
- Each session folder contains a per-session error log; a global error log lives in the main `pacu/` data dir.

For `lancer-pacu` parity, mirror this directory scheme exactly (resolved via the `directories` crate). Add a `--pacu-dir <path>` override flag (which upstream does not yet ship but is a frequent community request — surface it as an extension).

## 21 IAM privesc paths (Rhino canonical list, with API calls and detection signatures)

| # | Path | Permissions | Detection |
|---|------|-------------|-----------|
| 1 | CreatePolicyVersion --set-as-default | `iam:CreatePolicyVersion` | CloudTrail `CreatePolicyVersion` with `SetAsDefault=true` |
| 2 | SetDefaultPolicyVersion | `iam:SetDefaultPolicyVersion` | `SetDefaultPolicyVersion` from low-priv principal |
| 3 | EC2 RunInstances + PassRole | `iam:PassRole`, `ec2:RunInstances` | `RunInstances` with `IamInstanceProfile` to admin role |
| 4 | CreateAccessKey on other user | `iam:CreateAccessKey` | `CreateAccessKey` where caller != target user |
| 5 | CreateLoginProfile on other user | `iam:CreateLoginProfile` | `CreateLoginProfile` where caller != target |
| 6 | UpdateLoginProfile on other user | `iam:UpdateLoginProfile` | `UpdateLoginProfile` where caller != target |
| 7 | AttachUserPolicy (admin to self) | `iam:AttachUserPolicy` | `AttachUserPolicy` of `AdministratorAccess` or wildcard policy |
| 8 | AttachGroupPolicy | `iam:AttachGroupPolicy` | `AttachGroupPolicy` to caller's group |
| 9 | AttachRolePolicy | `iam:AttachRolePolicy` + `sts:AssumeRole` on target role | Attach admin policy to assumable role |
| 10 | PutUserPolicy (inline) | `iam:PutUserPolicy` | Inline policy with `Action:*` `Resource:*` |
| 11 | PutGroupPolicy | `iam:PutGroupPolicy` | Same, on group |
| 12 | PutRolePolicy | `iam:PutRolePolicy` + `sts:AssumeRole` | Same, on role |
| 13 | AddUserToGroup | `iam:AddUserToGroup` | `AddUserToGroup` into privileged group |
| 14 | UpdateAssumeRolePolicy | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Trust policy added a new principal |
| 15 | Lambda CreateFunction + Invoke + PassRole | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` | New Lambda with admin role + Invoke from suspect IP |
| 16 | Lambda + DynamoDB stream event source | `iam:PassRole`, `lambda:CreateFunction`, `lambda:CreateEventSourceMapping`, `dynamodb:*` | EventSourceMapping created against attacker-controlled table |
| 17 | UpdateFunctionCode on existing privileged Lambda | `lambda:UpdateFunctionCode` | `UpdateFunctionCode` followed by abnormal invocation |
| 18 | Glue CreateDevEndpoint + PassRole | `iam:PassRole`, `glue:CreateDevEndpoint` | CreateDevEndpoint with privileged role + SSH key |
| 19 | Glue UpdateDevEndpoint | `glue:UpdateDevEndpoint` | SSH public key replaced on existing endpoint |
| 20 | CloudFormation CreateStack + PassRole | `iam:PassRole`, `cloudformation:CreateStack` | CreateStack with role that has more privs than caller |
| 21 | Data Pipeline CreatePipeline + PutDefinition + PassRole | `iam:PassRole`, `datapipeline:CreatePipeline`, `datapipeline:PutPipelineDefinition` | CreatePipeline → PutDefinition → ActivatePipeline |

Modern additions (2024–2025, beyond the original 21):
- 22. **SSM SendCommand with PassRole on EC2 instance profile** → effective RCE as the instance profile role.
- 23. **CodeBuild CreateProject + PassRole** → execute buildspec as service role.
- 24. **SageMaker CreateNotebookInstance + PassRole**.
- 25. **EventBridge PutRule → Lambda Invoke with PassRole on target lambda**.

## Engineering hard parts

**Module discovery in Rust:** Python's runtime `import` is gone. Two approaches:
1. **Inventory crate** (`inventory = "0.3"`): each module file `inventory::submit! { Module { name: "iam__privesc_scan", run: |ctx, args| Box::pin(privesc_scan::run(ctx, args)) } }`. At startup, walk `inventory::iter::<Module>()`.
2. **Build-time codegen** with `build.rs` scanning `src/modules/**/mod.rs` and generating a `MODULES: &[Module]` slice.

Pick (1) — easier and aligns with the dynamic feel of the original.

**Session DB in Rust:** use `rusqlite` (sync) wrapped in `tokio::task::spawn_blocking` or `sqlx` (async). `sqlx` wins for ergonomics — `sqlx::SqlitePool` + compile-time SQL checks. Schema: one table per session metadata, JSON-serialized columns for enumerated resources (mirror Pacu's column-per-resource pattern). Migrations via `sqlx::migrate!`.

**REPL loop:** `rustyline` for line editing + history. Implement `set_session`, `list`, `search`, `run <module>`, `set_keys`, `swap_keys`, `whoami`, `data`, `services`, `regions`, `proxy`. Subcommand parsing per module via clap-derive embedded inside each module.

**Async boto3 equivalent:** `aws-config` + `aws-sdk-*` give a perfectly async client tree. Build a `AwsContext { config, region_cache, client_cache }` analogous to `pacu_main` and pass `&AwsContext` to every module's `run`.

**`iam__privesc_scan` Rust port:** input is the JSON `iam_users` / `iam_roles` / `iam_policies` from session DB. For each principal, evaluate the 21+ paths by:
1. Collecting effective permissions (managed + inline + group inheritance).
2. Pattern-matching against each privesc signature (`iam:CreatePolicyVersion`, etc.).
3. Optional `--scan-only` flag: report path without exploiting.
4. Otherwise emit step-by-step API call plan; with `--exploit`, actually call `aws-sdk-iam::Client::create_policy_version()` etc.

## Rust library mapping

```toml
[dependencies]
aws-config = "1.8"
aws-sdk-iam = "1.109"
aws-sdk-sts = "1.85"
aws-sdk-s3 = "1.133"
aws-sdk-ec2 = "1.150"
aws-sdk-lambda = "1.100"
aws-sdk-cloudwatchevents = "1.85"
aws-sdk-eventbridge = "1.85"
aws-sdk-glue = "1.85"
aws-sdk-cloudformation = "1.85"
aws-sdk-datapipeline = "1.85"
aws-sdk-cognitoidentityprovider = "1.85"
aws-sdk-ecs = "1.85"
aws-sdk-ecr = "1.85"
aws-sdk-eks = "1.85"
aws-sdk-rds = "1.110"
aws-sdk-secretsmanager = "1.85"
aws-sdk-ssm = "1.85"
aws-sdk-cloudtrail = "1.90"
aws-sdk-guardduty = "1.85"
aws-sdk-organizations = "1.85"
aws-sdk-route53 = "1.85"
aws-sdk-sns = "1.85"
aws-sdk-dynamodb = "1.85"

# Session DB
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite", "json", "chrono"] }

# REPL
rustyline = "14"
clap = { version = "4.5", features = ["derive"] }
inventory = "0.3"

# IAM policy parsing
serde_json = "1"
regex = "1.10"
aws-iam = "0.4"   # IAM policy DSL parser/evaluator (third-party crate)

# Proxy support (SOCKS pivoting)
hyper = "1"
hyper-socks2 = "0.10"

# Coloring + output
colored = "2"
comfy-table = "7"

# Async runtime
tokio = { version = "1.40", features = ["full"] }
```

## SDK-specific gotchas

- **Sessions vs keys:** unlike Pacu's session model, Rust SDK keeps creds in `SdkConfig`. Implement `set_keys`/`swap_keys` by rebuilding `SdkConfig` with `Credentials::from_keys(ak, sk, Some(token))` and a new `aws_credential_types::provider::SharedCredentialsProvider`.
- **Backdoor modules use write APIs:** every `*__backdoor_*` and `iam__privesc_scan --exploit` calls *write* APIs that **will** trigger GuardDuty `Discovery:IAMUser/AnomalousBehavior` and `Persistence:IAMUser/UserPermissions` findings. This is *expected* — Pacu is a red-team tool. Document loudly in CLI banner: "this generates noisy CloudTrail; only run with explicit authorization."
- **IMDS abuse:** for in-instance use, hit `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`. Use `reqwest` with strict IPv4 and a 1-second timeout (IMDSv2 needs `PUT /latest/api/token`).
- **STS GetFederationToken** is essential for the `sts__federation_token` style technique — `aws-sdk-sts::Client::get_federation_token()`.

## Validation environment

- **CloudGoat** (`rhinosecuritylabs/cloudgoat`) — Terraform-based intentionally vulnerable AWS scenarios. 14+ scenarios including `iam_privesc_by_attachment`, `lambda_privesc`, `ec2_ssrf`. The official Rhino lab; perfect for Pacu/clone testing.
- **AWSGoat** (`ine-labs/AWSGoat`) — web-app focused.
- **LocalStack Pro** for `iam`, `lambda`, `s3` simulation (note: privesc paths work but the actual elevation effect is a no-op since LocalStack doesn't enforce IAM).
- Burner AWS account + budget alert at $5/month + `aws-nuke` daily cron.

## 2024-2026 state

- Pacu development slowed in 2024; Rhino has been focused on CloudGoat updates. Last major release Aug 2024 (v1.6). Several modules need updating for SDK v2 boto3 changes.
- New modules contributed: `cognito__attack`, `eks__collect_tokens`. Several `*__bruteforce_*` style.
- Community fork [`pacu-community`] adds more modules. Not officially blessed.

### Research note — 2026-05-31 (deep-research pass)

Verified upstream module count + privesc-scan internals against `RhinoSecurityLabs/pacu` README, wiki, and DeepWiki module catalogue:

- **35+ modules** confirmed across enumeration / privesc / persistence / exfil / lateral / detection-evasion categories. Plan's earlier "~75 modules" overstated (counted CloudGoat helpers).
- **`iam__privesc_scan` algorithm.** Walks IAM permission graph, identifies 30+ documented escalation paths (single-step). Optional `--exec` flag actually executes the chain (vs scan-only default). Our equivalent must default to scan-only with a separate `--exec` to mirror the safety pattern.
- **`cognito__attack`** — exploits misconfigured Cognito user pools and identity pools (anonymous identity exchange, public sign-up + JWT enumeration, unauthenticated GetCredentialsForIdentity). New since 1.6.
- **`eks__collect_tokens`** — pulls service account tokens from compromised EC2 nodes running EKS pods, used for K8s lateral movement.
- **Session DB schema.** `sessions/<name>/sqlite.db` tables: `aws_keys`, `events`, `gather_log`, `attempted_modules`, `regions`, `permissions`. Our `redb`/`sqlx` schema mirrors verbatim so session import/export works bidirectionally with upstream.
- **`--dry-run` global flag (Lancer net-new).** Pacu upstream does NOT ship a dry-run mode — every write is real. Our Lancer-pacu adds `--dry-run` (default ON for write-class modules) wrapping every `aws-sdk-*` `Client::*` write call with intent logging. `--armed` required to actually mutate.

Sources: [RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu), [pacu wiki module details](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details), [pacu privesc modules DeepWiki](https://deepwiki.com/RhinoSecurityLabs/pacu/3.2-privilege-escalation-modules), [Pwned Labs Pacu privesc guide](https://blog.pwnedlabs.io/beginners-guide-to-hunting-for-aws-iam-privilege-escalations-with-pacu).

## Real-world authorized usage

Bug bounty: **only on programs that explicitly include AWS in scope** (Shopify, GitLab, HackerOne itself, some Bugcrowd programs). The hunter usually gets a contained sub-account or temporary credentials. Reporting requires:
- Full CloudTrail logs of the session.
- A `whoami` capture before/after.
- Module names + arguments used.
- No data exfiltration unless asked; for S3 dumps, prove access via head_object metadata only.

**Hard rule for clone:** include a `--dry-run` global flag that intercepts every `aws-sdk-*::Client::*` write call and logs intent without executing. Make it the default; require `--armed` to actually mutate state.

## AI augmentation ideas

- **Privesc path planner:** given enumerated permissions, LLM proposes a *chain* of the 21 paths to reach `iam:*` (e.g., path 8 → path 14 → path 3). Currently `iam__privesc_scan` only finds single-step paths.
- **Tabletop replay:** after a session, generate a narrative attack report (MITRE-mapped) suitable for bug bounty submission.
- **Module suggester:** given session DB state (e.g., "I just enumerated 12 unused IAM roles with `*`"), suggest the next module.
- **Detection coverage scoring:** for each executed module, predict which GuardDuty/CloudWatch alarms it would trip.

## Implementation phases (12 weeks)

| Week | Deliverable |
|------|-------------|
| 1 | REPL skeleton (rustyline), `Module` trait, inventory-based registration, `AwsContext`, basic commands (`list`, `search`, `whoami`) |
| 2 | Session DB schema (sqlx), `new_session`/`load_session`/`swap_keys`/`set_keys` |
| 3 | `aws__enum_account`, `iam__enum_users_roles_policies_groups`, `iam__get_credential_report` |
| 4 | `iam__enum_permissions` + IAM policy evaluator (effective-permission resolver) |
| 5 | `iam__privesc_scan` with all 21+ checks, `--scan-only` and `--exploit` modes |
| 6 | EC2/EBS/S3 enum modules + downloaders (`ebs__download_snapshots`, `s3__download_bucket`) |
| 7 | Lambda enum + 3 Lambda backdoor modules + CloudWatch Events triggers |
| 8 | Persistence: `iam__backdoor_users_keys`, `iam__backdoor_assume_role`, `ec2__backdoor_ec2_sec_groups` |
| 9 | Detection evasion: `detection__disruption`, `cloudtrail__download_event_history`, `guardduty__whitelist_ip` |
| 10 | Lateral movement: `organizations__assume_role`, `vpc__enum_lateral_movement` |
| 11 | Exfil: `rds__explore_snapshots`, `secrets__enum`, `systemsmanager__download_parameters` |
| 12 | `--dry-run` enforcement, SOCKS proxy support, session export/import (JSON), benchmark vs upstream Pacu |

---

## GUI (Lancer-standard pattern)

`lancer-pacu` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-pacu-cli` companion binary), but the **plain `lancer-pacu` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-pacu/`, `%APPDATA%\lancer-pacu\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-pacu-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-pacu.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-pacu.exe` (double-click opens the GUI window).
- Linux: `build/lancer-pacu` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-pacu` (bundled into `lancer-pacu.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-pacu/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-pacu.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-pacu-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-pacu
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-pacu.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-pacu-windows-x86_64\bin\lancer-pacu.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-pacu`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
