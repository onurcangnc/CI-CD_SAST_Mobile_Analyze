# CI-CD_SAST_Mobile_Analyze

This repository provides a basic CI/CD pipeline to perform static analysis on mobile applications. It uses **JADX** to decompile an APK, scans the source for secrets with **detect-secrets**, and searches for common security protections such as root or debug detection.

## GitHub Actions Workflow
The workflow defined in `.github/workflows/sast.yml` runs on every push or pull request to the `main` branch. It expects an APK named `app.apk` in the repository and performs the following steps:

1. Install required tools (JADX and Python packages).
2. Decompile the APK to `build/decompiled`.
3. Scan the decompiled source for secrets using `detect-secrets`.
4. Run `scripts/security_check.py` to check for security features like root detection, debug checks, and certificate pinning.
5. Uploads the results as workflow artifacts using `actions/upload-artifact@v4`.

## Scripts
- `scripts/security_check.py` – simple analyzer that searches the decompiled source for keywords indicating common security protections.

## Usage
Add your APK to the repository as `app.apk`, commit the changes, and push. The workflow will run automatically and attach a `sast-results` artifact with the analysis reports.
