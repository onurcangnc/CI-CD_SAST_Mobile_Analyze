# CI-CD_SAST_Mobile_Analyze

This repository provides a basic CI/CD pipeline to perform static analysis on mobile applications. It uses **JADX** to decompile an APK, scans the source for secrets with **detect-secrets**, and searches for common security protections such as root, emulator (including Genymotion) or debugger checks, Frida detection, and SSL pinning. The scanner relies on an extensive keyword list (for example `supersu`, `busybox`, `bluestacks`, `frida-gadget`, `isFridaProcessRunning`, `checkDebuggerAttached`, `isEmulator`, `trustkit`, and many others) compiled ahead of time for better efficiency. HTML reports are generated for both scans.

## GitHub Actions Workflow
The workflow defined in `.github/workflows/sast.yml` runs on every push or pull request to the `main` branch. It expects an APK named `app.apk` in the repository and performs the following steps:

1. Install required tools (JADX and Python packages). The workflow unsets common
   proxy variables before installing Python dependencies to avoid pip failures,
   and unzips the JADX archive with `-o` to prevent interactive prompts. The
   extracted directory is detected automatically so the build works even if the
   archive structure changes.
2. Decompile the APK to `build/decompiled`.
3. Scan the decompiled source for secrets using `detect-secrets` and generate a baseline.
4. Run `scripts/security_check.py` – analyzer that searches the decompiled source for evidence of root detection, emulator checks (including Genymotion), debugger checks, Frida detection and SSL pinning. It writes JSON and HTML reports and uses curated wordlists from several open-source projects. Patterns are precompiled and require at least two indicators for each category to reduce false positives.
5. Convert the secrets baseline and feature summary into HTML reports.
6. Uploads the results as workflow artifacts using `actions/upload-artifact@v4`. The generated baseline is saved to `build/detect-secrets-baseline.json`.

## Scripts
- `scripts/security_check.py` – analyzer that searches the decompiled source for evidence of root detection, emulator checks (including Genymotion), debugger checks, Frida detection and SSL pinning. It writes JSON and HTML reports and uses curated wordlists from several open-source projects. Patterns are precompiled and require at least two indicators for each category to reduce false positives.
- `scripts/baseline_to_html.py` – converts the `detect-secrets` JSON baseline into a simple HTML table for easier viewing.

## Usage
Add your APK to the repository as `app.apk`, commit the changes, and push. The workflow will run automatically and attach a `sast-results` artifact with the analysis reports.

### Updating the secrets baseline
`detect-secrets` works best when you maintain a baseline file. To generate a baseline locally, run:

```bash
detect-secrets scan > .secrets.baseline
```

You can then commit `.secrets.baseline` and update it with:

```bash
detect-secrets scan --baseline .secrets.baseline
```

This allows the pre-commit hook or CI pipeline to focus only on newly introduced secrets.
