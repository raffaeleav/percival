excluded_exts = {
    ".a", ".aac", ".avi",
    ".bak", ".bin", ".bmp", ".b2",
    ".class", ".ckpt",
    ".dat", ".dat-old", ".debug", ".dll", ".dylib",
    ".exe",
    ".flac", ".gif", ".gpg", ".gz",
    ".h5",
    ".ico", ".idx",
    ".jpg", ".jpeg",
    ".lock", ".log",
    ".mkv", ".mo", ".model", ".mov", ".mp3", ".mp4",
    ".npy", ".npz",
    ".o", ".ogg", ".old",
    ".pb", ".pdf", ".pm", ".png", ".po", ".pot", ".psd", ".pyc",
    ".qm",
    ".rar",
    ".sig", ".so", ".state", ".strings", ".svg", ".svgz",
    ".tar", ".tgz", ".tiff", ".tmp", ".trace", ".ts", ".ttf",
    ".wav", ".webp", ".whl",
    ".xz",
    ".zip", ".7z"
}

excluded_dirs = {
    "/bin",
    "/boot",
    "/dev",
    "/etc/ssh/moduli",
    "/lib", "/lib64",
    "/proc",
    "/sbin",
    "/sys",
    "/usr/bin", "/usr/include", "/usr/lib", "/usr/lib64", 
    "/usr/local/lib", "/usr/sbin", "/usr/share", "/usr/src",
    "/var/cache", "/var/lib", "/var/log"
}

excluded_cache_dirs = {
    ".cache",
    ".gradle/caches",
    ".m2/repository",
    ".npm",
    "__pycache__",
    "node_modules",
}

key_patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key).{0,5}[0-9A-Za-z/+]{40}",
    "Azure Storage Key": r"(?i)(accountkey|primary|secondary)[^\S\r\n]*=[^\S\r\n]*[a-zA-Z0-9+/=]{88}",
    "Azure SAS Token": r"se=[0-9T:Z]+&sp=[a-z]+&sv=\d{4}-\d{2}-\d{2}",
    "Discord Token": r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "Firebase API Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{20,255}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "Google Cloud API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud Account Key": r"\"private_key\":\s*\"-----BEGIN PRIVATE KEY-----",
    "Google OAuth Refresh Token": r"1//[0-9A-Za-z_-]{50,200}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9._-]+?\.[a-zA-Z0-9._-]+",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",    
    "PayPal Secret": r"EA[a-zA-Z0-9]{84}",
    "RSA Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9_/-]{20,}",
    "Stripe Live Key": r"sk_live_[0-9A-Za-z]{16,}",
    "Stripe Publishable Key": r"pk_(live|test)_[0-9A-Za-z]{24}",
    "Stripe Test Key": r"sk_test_[0-9A-Za-z]{16,}"
}
