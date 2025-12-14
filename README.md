# Firebase Sniper

Tool to detect common Firebase security misconfigurations in Android APKs.

It extracts Firebase configuration from APK files and tests for:
- Public Firebase Realtime Database access
- Open Firebase Storage buckets
- Exposed Firebase Remote Config
- Unauthorized Firebase email/password signup

Intended for **authorized security testing and bug bounty research**.

---

## Usage

```bash
usage: firebase-sniper.py [-h] [--apk-path APK_PATH] [--user-email USER_EMAIL] [--output OUTPUT] [--user-agent USER_AGENT]

Firebase Sniper - Test Firebase security misconfigurations in APKs and Web Apps

options:
  -h, --help              show this help message and exit
  --apk-path APK_PATH     Path to the APK file or folder containing APKs for testing
  --user-email USER_EMAIL Email address to use for unauthorized signup testing (default: random email)
  --output OUTPUT         Path to the output file (default: firebase_sniper_results.txt)
  --user-agent USER_AGENT Custom User-Agent for HTTP requests (default: BUGBOUNTY)
```

---

## Credits

This project is based on the original work by Suryesh:
https://github.com/Suryesh/Firebase-Checker
The code has been heavily modified and adapted for automated bug bounty usage.
