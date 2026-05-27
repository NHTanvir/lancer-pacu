//! Module registration hub.
//!
//! Each `pub mod` declaration here causes the module file to be compiled,
//! which fires its `inventory::submit!` at program startup and registers the
//! module in the global inventory.

pub mod aws_enum_account;
pub mod iam_enum_users_roles_policies_groups;
pub mod iam_get_credential_report;
pub mod iam_enum_permissions;
pub mod iam_privesc_scan;
pub mod ec2_enum;
pub mod ebs_enum_volumes_snapshots;
pub mod ebs_download_snapshots;
pub mod s3_download_bucket;
pub mod lambda_enum;
pub mod lambda_backdoor_new_roles;
pub mod lambda_backdoor_new_sec_groups;
pub mod lambda_backdoor_new_users;
pub mod iam_backdoor_users_keys;
pub mod iam_backdoor_assume_role;
pub mod ec2_backdoor_ec2_sec_groups;
pub mod detection_enum_services;
pub mod detection_disruption;
pub mod cloudtrail_download_event_history;
pub mod guardduty_whitelist_ip;
