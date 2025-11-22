excluded_files = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp",
    ".mp3", ".wav", ".flac", ".aac", ".ogg",
    ".mp4", ".mkv", ".mov", ".avi",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".o", ".a",
    ".pdf", ".sqlite", ".db", ".psd", ".ico",
}

excluded_dirs = {
    "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/lib", "/lib64",
    "/usr/lib", "/usr/lib64",
}

key_patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key).{0,5}[0-9A-Za-z/+]{40}",

    "GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GCP Service Account Key (JSON)": r"\"private_key\": \"-----BEGIN PRIVATE KEY-----[\\s\\S]+?END PRIVATE KEY-----\"",

    "Azure Storage Key": r"(?i)(accountkey|primary|secondary)[^\S\r\n]*=[^\S\r\n]*[a-zA-Z0-9+/=]{88}",
    "Azure SAS Token": r"se=[0-9T:Z]+&sp=[a-z]+&sv=\d{4}-\d{2}-\d{2}",

    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9_/-]{20,}",

    "Stripe Live Key": r"sk_live_[0-9A-Za-z]{24}",
    "Stripe Test Key": r"sk_test_[0-9A-Za-z]{24}",
    "Stripe Publishable Key": r"pk_(live|test)_[0-9A-Za-z]{24}",
    "PayPal Secret": r"EA[a-zA-Z0-9]{84}",

    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[0-9a-fA-F]{32}",

    "Firebase API Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Google OAuth Refresh Token": r"1//[0-9A-Za-z_-]{50,200}",

    "JWT Token": r"eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9._-]+?\.[a-zA-Z0-9._-]+",

    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",

    "Heroku API Key": r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Discord Token": r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
}
