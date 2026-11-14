---
name: high_quality_mr_wave_loop
description: Continuous high-quality focused multi-branch MR wave loop with pairwise-disjoint file locks, AST anti-boilerplate verification, and 6-gate local pre-push CI parity checks.
---

# Continuous High-Quality Focused MR Wave Loop (`high_quality_mr_wave_loop`)

This skill defines the standard operating procedure and automation engine ([`scripts/devops/mr_wave_loop_engine.py`](../../../scripts/devops/mr_wave_loop_engine.py)) for continuously rolling out waves of **focused, conflict-free, deeply tested branches** ready for 1-click Merge Request creation on `gitlab.cluster.example.org`.

---

## 1. Core Design Principles (Why This Loop Works Without Bogging Down GitLab)

1. **Focused Single-Responsibility Scope (`2–4` Cohesive Files per Branch):**
   * Each branch in a wave addresses **one concrete, high-value architectural, security, observability, or DevOps problem** (typically `1` reusable tool/module under `scripts/`, `1` comprehensive `unittest` suite under `tests/` with positive, negative, and corner-case assertions, and `1` architecture/runbook note under `.ai/knowledge/`).
2. **Strict Pairwise File-Scope Disjointness (`0` Merge Conflicts):**
   * Every branch $B_i$ in a wave is branched directly off `origin/main` and satisfies:
     $$\text{Files}(B_i) \cap \text{Files}(B_j) = \emptyset \quad \forall i \neq j$$
   * Because file sets are pairwise disjoint, the human reviewer can open and merge the MRs in **any order** with zero merge conflicts and zero rebase cascades.
3. **AST Anti-Boilerplate & Real-Manifest Parsing Gate:**
   * Branches must **never** be generated from a shared parameterized string template that only swaps threshold numbers.
   * [`mr_wave_loop_engine.py`](../../../scripts/devops/mr_wave_loop_engine.py) inspects the Python AST of every branch's implementation and test modules to verify:
     * Real repository manifest parsing (`Chart.yaml`, `Chart.lock`, `values.yaml`, `*.csproj`, `package.json`, `renovate.json`, K8s YAML manifests, Prometheus rules) or live protocol/contract verification.
     * Pairwise AST structural & identifier distinctness across all branches in the wave (`similarity < 0.70`).
4. **Local 6-Gate Pre-Commit & Pre-Push Verification (`scripts/githooks/pre-commit` & `pre-push`):**
   * Every branch is verified **locally** before `git push` so broken commits never bog down the GitLab runner queue:
     1. **Unit, Negative-Path & Corner-Case Tests (`unittest`)**
     2. **Local Helm Linter & Go `text/template` Variable Check (`tls_trust.lint_all_helm_charts`)** — catches unescaped `{{ $labels.instance }}` / `{{ $value }}` variables across all 18 Helm charts.
     3. **Helm `Chart.lock` SHA-256 HashReq Sync (`tls_trust.verify_all_helm_chart_locks`)** — verifies all 6 lockfiles.
     4. **AICaC `SKILL.md` Strict YAML Frontmatter Check (`sanitize_and_validate_skills`)** — verifies all skills parse under Go `yaml.v3`.
     5. **Strict `LF` Line Endings & OPSEC Secret Scan (`devenv.run_precommit_checks`)** — enforces Rule 5 (`\n` only) and Rule 12 (zero hardcoded secrets/WAN IPs).
     6. **Conventional Commit & Issue Traceability (`devenv.check_commit_message`)** — enforces Rule 7 (lowercase subject `<= 100` chars with `(refs #<id>)`).
5. **Rule 4 & Rule 2 Compliance (1-Click Compare & New MR Links):**
   * AI agents **never** open or merge Merge Requests via API. Instead, the loop pushes verified branches to `origin` and outputs a clean **1-Click MR Launchpad Table** with both the **GitLab Compare Link** (`/-/compare/main...<branch>`) and the **1-Click Pre-Filled New MR Link** (`/-/merge_requests/new?merge_request[source_branch]=...`).

---

## 2. Iterative Loop Workflow

For each branch $B_i$ in a planned wave:

1. **Checkout Fresh Branch from `origin/main`:**
   * Write `-b\n<branch_name>\nmain\n` to `<cli-args>` and invoke the Rule 9 pre-approved `git checkout` runner.
2. **Implement Focused Domain Module, Corner-Case Tests & Knowledge Note:**
   * Ensure all files are written with strict `LF` (`\n`) line endings and parse real repository manifests or contracts.
3. **Run Local Verification & Wave Audit:**
   * Execute the branch's unit test suite and `python scripts/devops/inline_docs_migration.py verify`.
4. **Stage, Commit & Push via Rule 9 Pre-Approved Runners:**
   * `scripts/githooks/pre-commit`, `scripts/githooks/commit-msg`, and `scripts/githooks/pre-push` automatically run `python scripts/devops/devenv.py hooks run` locally before the branch reaches `gitlab.cluster.example.org`.
5. **Return to `main` and Advance to Next Disjoint Branch in the Loop:**
   * Switch back to `main`, verify clean working tree, and repeat for the next focused branch in the wave.

---

## 3. Pairing with Antigravity Slash Commands (`/goal`, `/schedule`)

* **`/goal`:** When the user wants the agent to run a continuous multi-wave loop autonomously until a target backlog or quality goal is met, recommend `/goal`.
* **`/schedule`:** When the user wants a recurring wave audit or nightly readiness loop, recommend `/schedule`.
