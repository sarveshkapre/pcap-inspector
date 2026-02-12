# INCIDENTS

## Policy
- Record only real failures, regressions, or reliability incidents.
- Each incident must include root cause, impact, detection, fix, and prevention rule.

## Incidents
- None recorded as of 2026-02-09.

## Incident Template
- Date:
- Title:
- Impact:
- Detection:
- Root Cause:
- Resolution:
- Prevention Rule:
- Evidence (files/tests/commands):

### 2026-02-12T20:01:28Z | Codex execution failure
- Date: 2026-02-12T20:01:28Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-pcap-inspector-cycle-2.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:04:55Z | Codex execution failure
- Date: 2026-02-12T20:04:55Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-pcap-inspector-cycle-3.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:08:24Z | Codex execution failure
- Date: 2026-02-12T20:08:24Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-pcap-inspector-cycle-4.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:11:52Z | Codex execution failure
- Date: 2026-02-12T20:11:52Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-pcap-inspector-cycle-5.log
- Commit: pending
- Confidence: medium
