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
