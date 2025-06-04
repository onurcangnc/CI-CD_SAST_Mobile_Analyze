# CI-CD_SAST_Mobile_Analyze

This repository provides a basic CI/CD pipeline to perform static analysis on mobile applications. It uses **JADX** to decompile an APK, scans the source for secrets with **detect-secrets**, and searches for common security protections such as root, emulator (including Genymotion) or debugger checks, Frida detection, and SSL pinning. The scanner relies on an extensive keyword list (for example `supersu`, `busybox`, `bluestacks`, `frida-gadget`, `trustkit`, and many others) compiled ahead of time for better efficiency.

## GitHub Actions Workflow
The workflow defined in `.github/workflows/sast.yml` runs on every push or pull request to the `main` branch. It expects an APK named `app.apk` in the repository and performs the following steps:

1. Install required tools (JADX and Python packages).
2. Decompile the APK to `build/decompiled`.
3. Scan the decompiled source for secrets using `detect-secrets`.
4. Run `scripts/security_check.py` to check for security features like root detection, emulator checks (Genymotion included), debugger detection, Frida detection, and SSL pinning.
5. Uploads the results as workflow artifacts using `actions/upload-artifact@v4`.

## Scripts
- `scripts/security_check.py` – analyzer that searches the decompiled source for evidence of root detection, emulator checks (including Genymotion), debugger checks, Frida detection and SSL pinning. It uses curated wordlists from several open-source projects. Patterns are precompiled and require at least two indicators for each category to reduce false positives while improving performance.

## Usage
Add your APK to the repository as `app.apk`, commit the changes, and push. The workflow will run automatically and attach a `sast-results` artifact with the analysis reports.
