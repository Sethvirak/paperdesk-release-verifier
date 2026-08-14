# PaperDesk release verifier

This public repository is an independent workflow/control root for PaperDesk release verification. It contains no PaperDesk application source, runtime artifact, production evidence, credential, or customer data.

The reusable verifier:

- runs with read-only caller permissions and no cloud identity;
- checks out the caller's exact release commit without persisted credentials;
- reconstructs the expected package before downloading the producer artifact;
- treats the downloaded artifact as hostile input;
- runs an independently versioned standard-library verifier over the archive, manifests, release materials, SBOMs, and provenance;
- publishes only a verified artifact and digest-bound JSON receipt into the caller's workflow run.

The deadline watchdog is separately scheduled. It remains inactive until its repository variables and secrets are configured. When active, it reads a bounded HTTPS state record, validates the 24-hour candidate deadline, and dispatches only the exact accepted rollback coordinates when an overdue candidate is still live. It never logs credentials and writes a decision/dispatch receipt artifact on each exercised run.

The `azure-production-control.yml` reusable workflow is the only public control that may request GitHub OIDC. Only its read-only canary is currently exercisable; every mutating operation is rejected before Azure login. The canary validates the exact reusable `job.workflow_ref`, `job.workflow_sha`, caller commit, repository, subscription, and fixed production App Service resource. The accepted-release code is dormant, reviewable scaffolding for binding release, caller, candidate-run, acceptance-run, evidence-run, artifact-ID/digest, receipt, verifier-workflow/job, environment, and live locked-WORM coordinates. It is not activation-ready and must not be treated as permission to start the bridge or write Azure Storage.

## Pinning model

Verifier scripts are pinned inside reusable workflows to an earlier immutable full commit SHA. PaperDesk callers pin the reusable workflow itself to a later full commit SHA. This two-commit update process avoids a circular self-reference:

1. merge and test verifier script changes;
2. update the workflow's internal script checkout to that full SHA and merge;
3. update the PaperDesk caller to the new workflow full SHA;
4. update the Azure federated-identity subject only after review so it requires the exact `azure-production-control.yml` `job_workflow_ref` and the protected `paperdesk-production-control` environment;
5. run the read-only canary and prove the old PaperDesk workflow can no longer obtain a token before enabling any mutating operation.

Never call a branch or tag from a production workflow. Never place application bytes or evidence in this public repository.

## Local verification

```bash
python -m unittest discover -s tests -v
python -m py_compile scripts/verify_candidate.py scripts/check_deadline.py scripts/accepted_release_registry.py
```

## Accepted-release registry contract

The registry helper preserves the exact 12 verified-artifact top-level files, all five exact files under `paperdesk-prebuild-release-materials/`, the external candidate-verification receipt, and the production-acceptance receipt. It builds a deterministic, bounded request and permits only this fixed destination:

`https://mdspdbak2608089c4e.blob.core.windows.net/paperdesk-accepted-releases/v1/releases/<candidate-sha>/<candidate-run-id>/<acceptance-run-id>/`

The request binds candidate and acceptance run attempts inside the manifest rather than weakening the stable path. Each of the 19 preserved files has an exact relative path, byte size, SHA-256, and Content-MD5. It binds PaperDesk's actual protected-main source workflow ref (`@refs/heads/main`) while independently binding immutable execution through the fetched run ID, path, head SHA, branch, event, and attempt. It also binds exact GitHub artifact IDs and immutable artifact digests, the `post-deploy` evidence name and bundle digest, the source-compatible `fully-accepted` 17-field receipt, the external verifier workflow full SHA/job/run, `production` environment, and a separately observed locked 30-day WORM policy snapshot. The dormant bridge helper is designed to upload each payload blob with `If-None-Match: *`, read it back through the distinct read-only managed identity, accept only bounded create-only overwrite error codes, prove overwrite and out-of-prefix negatives, and upload `registry-manifest.json` last as the sole completeness marker. A retry may only validate an identical completed entry.

The fixed helper command is `python3 accepted_release_registry.py serve` and the only mutation endpoint is `POST /internal/v1/persist-accepted-release`. The fixed bridge is `paperdesk-release-registry-bridge-9c4e0d0d` in `rg-master-data-structure-sea`, while the fixed registry storage account and container remain in `rg-paperdesk-rollback-sea-20260808`; resource names and prefixes are not caller inputs. The bridge must be stopped, public access disabled, main and SCM defaults denied, FTPS disabled, and FTP/SCM basic publishing disabled before and after every attempt. The writer user-assigned identity needs create/add only; the separate reader identity needs read only. Bridge cleanup is fail-closed, removes the one-run session-token digest, and may not delete accepted-release blobs.

Current status: independent approval of this PR can approve only the dormant read-only canary and registry scaffolding. It does not approve any mutation. An exact-workflow federated credential and a successful read-only canary are still required, but they are not sufficient for activation. A later, separately reviewed design must also provide (1) independent verification of hostile artifact bytes or a GitHub-signed producer attestation, (2) a fixed post-acceptance caller that runs only after the acceptance run has completed successfully, (3) exact read authorization and a live canary for the locked WORM policy, (4) an ARM-triggerable in-VNet transport that does not open the private bridge to a GitHub-hosted runner, and (5) live proof of the add-only overwrite response. The exact helper deployment is a separate bootstrap prerequisite. Until all of these are implemented, canaried, and independently approved, all mutating modes exit before Azure login. Do not add a secret, branch/tag workflow reference, caller-controlled Azure resource, public bridge ingress, SCM exception, or broad Storage role as a shortcut.

## Watchdog configuration

The scheduled watchdog runs only when `PAPERDESK_WATCHDOG_MODE` equals `accepted-release-deadline-v1`. It also requires:

- variable `PAPERDESK_WATCHDOG_STATE_URL`: credential-free HTTPS URL with no query, fragment, or user info;
- variable `PAPERDESK_WATCHDOG_STATE_HOST`: exact expected lower-case host;
- variable `PAPERDESK_SOURCE_REPOSITORY`: exact `owner/repository` to dispatch;
- variable `PAPERDESK_WATCHDOG_RUNBOOK_URL`: credential-free HTTPS operator runbook;
- secret `PAPERDESK_WATCHDOG_STATE_TOKEN`: read-only bearer credential for the state object;
- secret `PAPERDESK_ROLLBACK_DISPATCH_TOKEN`: fine-grained token limited to Actions write on the source repository.

Do not set the source repository's `PAPERDESK_PRODUCTION_WATCHDOG_CONFIGURED` gate until a scheduled run and an overdue-candidate drill both have retained receipts.
