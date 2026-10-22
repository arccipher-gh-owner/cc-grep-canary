# cc-grep-canary (lab)

Throwaway public repo for a **zero-cost** hosted check of Claude Code's default `Grep` vs `Read` on `/proc/self/environ`.

- Model traffic is a **local scripted** `/v1/messages` stand-in on the runner (`ANTHROPIC_BASE_URL=http://127.0.0.1:8899`). No Anthropic spend.
- Comment bodies are filtered to **`CANARY-*` lines only**. Live `ghs_` / `ghp_` values are not copied into the issue.
- Actor under test: `arccipher-gh-outsider` via `allowed_non_write_users`.
