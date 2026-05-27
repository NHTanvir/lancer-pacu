CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    active INTEGER NOT NULL DEFAULT 0,

    -- AWS key fields
    -- NOTE: secret_access_key is stored in plaintext (mirrors Pacu's behaviour).
    --       Do not commit sessions.sqlite to version control.
    access_key_id TEXT,
    secret_access_key TEXT,
    session_token TEXT,
    key_alias TEXT,
    region TEXT DEFAULT 'us-east-1',

    -- Cached enumeration data (JSON blobs, mirrors Pacu's column-per-resource pattern)
    iam_users TEXT DEFAULT '[]',
    iam_roles TEXT DEFAULT '[]',
    iam_groups TEXT DEFAULT '[]',
    iam_policies TEXT DEFAULT '[]',
    iam_permissions TEXT DEFAULT '{}',

    ec2_instances TEXT DEFAULT '[]',
    ec2_security_groups TEXT DEFAULT '[]',
    ec2_amis TEXT DEFAULT '[]',
    ec2_volumes TEXT DEFAULT '[]',
    ec2_snapshots TEXT DEFAULT '[]',

    s3_buckets TEXT DEFAULT '[]',
    lambda_functions TEXT DEFAULT '[]',

    -- Generic catch-all for additional services
    extra TEXT DEFAULT '{}'
);
