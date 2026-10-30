# Security & Privacy

SecureVault is built **safety first**: it protects your files without ever sending them, or anything about them, anywhere you didn't ask for.

## Privacy promises

- **No accounts, ads, analytics or telemetry.** SecureVault never phones home.
- **Your data stays on your PC.** Logs, the baseline, quarantined files and imported signatures are stored locally
  (`%LOCALAPPDATA%\SecureVault` for the Windows app, next to `main.py` when run from source) and are excluded from git.
- **Nothing is deleted without you.** Scans only report. Quarantine needs a click, and it is reversible until you choose *Delete*.
  Restore and delete always ask first. When Microsoft Defender is used as a second engine, it runs with remediation disabled.
- **Microsoft Defender stays in charge.** SecureVault works alongside it and never changes Windows security settings.

## Live stream safeguards

The live stream is the only feature that shares anything, and only while you have it switched on.

| Safeguard | What it does |
| :--- | :--- |
| Off by default, this PC only | The stream binds to `127.0.0.1` unless you allow your network or the internet, and both ask for confirmation first |
| Read-only | Viewers can look; nothing can be changed through the stream |
| 128-bit secret links | A new random token every time streaming starts; stopping the stream revokes every shared link |
| Privacy mode (on by default) | Viewers see file names only, never folder paths or your Windows user name |
| Internet links expire | Cloudflare tunnel links close automatically after 2 hours |
| Viewer alerts | You get a notice in the activity feed whenever someone opens your stream |
| Brute-force lockout | A device that sends 10 wrong links in 10 minutes is blocked for 15 minutes |
| DNS-rebinding protection | Requests with an unexpected `Host` header are rejected |
| Resource limits | At most 25 viewers and 64 simultaneous requests |
| Strict browser headers | CSP, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP and a restrictive `Permissions-Policy` |

Only share stream links with people you trust, and only allow your network on networks you trust (home Wi-Fi, not public Wi-Fi).

## Verifying downloads

Download SecureVault only from the [official website](https://kirangautham-82899.github.io/SecureVault-Ransomware-Detection-Prevention-System/)
or [GitHub Releases](https://github.com/kirangautham-82899/SecureVault-Ransomware-Detection-Prevention-System/releases).
Every release is built by GitHub Actions from the public source and lists its SHA-256 checksum (also in `SHA256SUMS.txt`):

```powershell
(Get-FileHash .\SecureVault-Windows.zip).Hash
```

The app is not code-signed, so Windows SmartScreen may warn on first launch. Verify the checksum, then choose **More info → Run anyway**.

## Supply chain

- Python dependencies are pinned in `requirements.txt`. Dependabot proposes updates weekly for packages and GitHub Actions.
- Workflows run with least privilege: tests are read-only, and only the release job may write releases.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/kirangautham-82899/SecureVault-Ransomware-Detection-Prevention-System/security/advisories/new)
instead, with steps to reproduce. You'll get a reply as soon as possible, and fixes are released as a new version.
