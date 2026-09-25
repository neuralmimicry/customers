Overview: Improve Customers through the Conductor execution loop.

Delivery Context:
- Current stage: development
- Validated stages: none
- Rollout strategy: canary

Requirements Register:
- REQ-001: Inspect and record current repository, runtime, or job evidence before selecting an operation.
- REQ-002: Implement only the scoped change, job update, or progress-monitoring action supported by that evidence.
- REQ-003: Preserve secure, resilient behaviour and avoid destructive commands.
- REQ-004: Update or add tests covering the changed path, or provide the relevant live operational check.
- REQ-005: Run verification commands and report the outcome.
- REQ-006: Leave unrelated files untouched.
- REQ-007: Record rollback/recovery steps and the acceptance signal proving the gap is closed.
- REQ-008: Preserve staged progression and rollout governance metadata.
- REQ-009: Capture a fresh protected-target readiness baseline before any change.
- REQ-010: Use the selected canary or red-green rollout strategy and verify the post-rollout health window.
- REQ-011: Automatically revert the exact produced commit without rewriting history if health or verification degrades.
- REQ-012: Verify rollback readiness and recovery before finalising the delivery.
- REQ-013: When runtime rollout or restart work is needed, use the available Ansible automation context: {"ansible_root":"/srv/swarmhpc/ansible","config_path":"/srv/swarmhpc/ansible/ansible.cfg","host_targets":["rk1"],"hosts":["spirit"],"inventory_path":"/srv/swarmhpc/ansible/inventory/hosts.ini","playbooks":["continuum_tenant_customers_site.yml","continuum_tenant_nmchain_site.yml"],"repo_root":"/srv/swarmhpc","roles_path":"/srv/swarmhpc/ansible/roles","secrets_root":"/srv/swarmhpc/ansible/.secrets"}.

Work Item Summary:
customers is linked to live services but no obvious test capability was discovered in the repository inventory. Establish at least a minimal regression or smoke-test baseline before deeper autonomous changes.

Authoritative delivery constraints (mandatory; implement and verify these, do not merely describe them):
- No structured delivery constraints were supplied; follow the work-item summary exactly.

Plan JSON:
{"action":"establish_repository_test_baseline","finding_id":"866ba4c0-367c-4f6a-824d-689ef5b0a769","finding_key":"repository_test_baseline:neuralmimicry/customers","linked_services":["customers"],"repository":"neuralmimicry/customers"}

Planner guidance (advisory; it must not weaken or contradict the authoritative work-item requirements):
Overview: This work item establishes a test baseline for the Customers service, which is linked to live services but currently lacks executable project-native validation. The baseline will cover critical regression and smoke-test paths, enabling safe autonomous changes through a canary rollout strategy.

Requirements Register:
- REQ-001: Inspect the NeuralMimicry/Customers repository and runtime state to identify existing test coverage gaps and evidence of uncertainty.
- REQ-002: Verify control-plane connectivity and worker node probes using kubectl before proceeding with validation.
- REQ-003: Review service health logs and metrics on host 'spirit' to identify specific degradation causes or operational context.
- REQ-004: Execute an Ansible syntax check on the site playbook to validate configuration without applying changes.
- REQ-005: Generate a minimal test script or CI job definition to cover critical smoke-test paths for the Customers service.
- REQ-006: Integrate the new test baseline into the existing CI/CD pipeline to enable automated verification.
- REQ-007: Execute a canary rollout to validate runtime stability before full deployment.
- REQ-008: Monitor post-rollout readiness health windows and prepare automatic rollback procedures if degradation is detected.
- REQ-009: Ensure all changes are non-destructive, resilient, and secure, avoiding bypass of staged delivery gates.
- REQ-010: Provide explicit verification evidence of successful baseline establishment and rollout completion.

Notes: The plan prioritises incremental, test-backed implementation. It assumes the repository is accessible and the cluster is healthy. If evidence is insufficient, the plan should recommend further investigation before proceeding.


Protected rollout contract (mandatory): capture a fresh readiness baseline before any change; use the selected canary or red_green strategy; verify health throughout the post-rollout window; if health or verification degrades, automatically revert the exact produced commit without rewriting history, rerun tests and GitHub Actions, and verify recovery.