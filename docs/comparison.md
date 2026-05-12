# Comparison

Linwarden is intentionally narrow. It is built for rootless host posture triage and CI artifacts, not full compliance automation.

| Tool category | Strong fit | Linwarden difference |
| --- | --- | --- |
| Linwarden | Rootless Linux hardening checks, mounted-root scans, Markdown/JSON/SARIF artifacts. | Small read-only scanner with zero runtime dependencies. |
| Lynis-style host audit | Broad interactive host auditing. | Linwarden favors deterministic CI output and fixture-root scanning over broad local inspection. |
| OpenSCAP-style compliance | Formal benchmark and policy evaluation. | Linwarden is not a compliance engine; it provides explainable triage findings. |
| osquery-style fleet telemetry | Querying live fleets through a SQL-like interface and agents. | Linwarden does not run an agent or require a control plane. |
| Shell hardening scripts | One-off local checks and remediation. | Linwarden does not mutate host state and emits stable machine-readable reports. |

## Best Use Cases

- CI jobs that need SARIF or Markdown output.
- Golden image checks before publishing a VM or container base image.
- Offline investigation of mounted Linux roots.
- Small teams that want a lightweight hardening signal before investing in heavier compliance tooling.
- Open source projects that want security posture checks without privileged CI runners.

## Poor Fits

- Environments that need full CIS, DISA STIG, or regulatory attestation.
- Continuous fleet telemetry with central query history.
- Automated remediation or host mutation.
- Deep vulnerability management tied to package CVE feeds.

Linwarden can complement those systems by catching obvious posture issues early and producing artifacts that are easy to review in pull requests and scheduled jobs.
