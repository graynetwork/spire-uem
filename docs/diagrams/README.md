# Diagrams

Each `.drawio` file is the editable source; the `.svg` beside it is what the [README](../../README.md) shows.

| Source | Shows |
|---|---|
| `architecture.drawio` | Control plane, PostgreSQL, managed endpoint, offline release signing |
| `enrollment-and-trust.drawio` | Enrollment, mTLS check-in, PCR baselines and secret gating |
| `fleet-data-flow.drawio` | Inventory and sensors, device attributes, dynamic groups, workflows |
| `patch-campaigns.drawio` | Campaign lifecycle, stage promotion, per-device dispatch |
| `signed-updates.drawio` | Release signing, agent verification, automatic rollback |

## Editing

Open a `.drawio` file in [draw.io](https://www.drawio.com/) (desktop or web), edit it, save it, then run `./export.sh` from this directory to regenerate the SVGs. Commit both files.

Use the same colours as the existing diagrams: blue for the control plane, green for the endpoint, yellow for stored data, red for security-sensitive steps and failures, purple for decisions, grey for external systems.
