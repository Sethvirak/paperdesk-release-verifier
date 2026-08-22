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

The `azure-production-control.yml` reusable workflow is the only public control that may request GitHub OIDC. Only its read-only canary is currently exercisable; every mutating operation is rejected before Azure login. The canary validates the exact reusable `job.workflow_ref`, `job.workflow_sha`, caller commit, repository, subscription, and fixed production App Service resource. The accepted-release implementation is source-complete for independent review: it binds release, caller, candidate-run, acceptance-run, evidence-run, artifact-ID/digest, receipt, verifier-workflow/job, environment, and live locked-WORM coordinates. The global pre-login hard stop still makes it non-operational and must not be treated as permission to start the bridge or write Azure Storage.

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
python -m py_compile scripts/verify_candidate.py scripts/check_deadline.py scripts/accepted_release_registry.py scripts/build_registry_webjob.py
python scripts/build_registry_webjob.py --output /tmp/paperdesk-accepted-release-registry-webjob.zip
```

## Accepted-release registry contract

The registry helper preserves the exact 12 verified-artifact top-level files, all five exact files under `paperdesk-prebuild-release-materials/`, the external candidate-verification receipt, and the production-acceptance receipt. It builds a deterministic, bounded request and permits only this fixed destination:

`https://mdspdbak2608089c4e.blob.core.windows.net/paperdesk-accepted-releases/v1/releases/<candidate-sha>/<candidate-run-id>/<acceptance-run-id>/`

The request binds candidate and acceptance run attempts inside the manifest rather than weakening the stable path. Each of the 19 preserved files has an exact relative path, byte size, SHA-256, and Content-MD5. It binds PaperDesk's actual protected-main source workflow ref (`@refs/heads/main`) while independently binding immutable execution through the fetched run ID, path, head SHA, branch, event, and attempt. It also binds exact GitHub artifact IDs and immutable artifact digests, the `post-deploy` evidence name and bundle digest, the source-compatible `fully-accepted` 17-field receipt, the external verifier workflow full SHA/job/run, `production` environment, and a separately observed locked 30-day WORM policy snapshot. The dormant bridge helper is designed to upload each payload blob with `If-None-Match: *`, read it back through the distinct read-only managed identity, accept only bounded create-only overwrite error codes, prove overwrite and out-of-prefix negatives, and upload `registry-manifest.json` last as the sole completeness marker. A retry may only validate an identical completed entry.

The selected dormant transport is a fixed triggered WebJob, not public or SCM ingress. `python scripts/build_registry_webjob.py --output <unused-path>.zip` creates a deterministic three-file deployment package under `App_Data/jobs/triggered/paperdesk-accepted-release-registry/`: the fixed runner, singleton `settings.job`, and standard-library helper. The runner verifies the helper digest and invokes `python3 -I accepted_release_registry.py` only for `runtime-canary` or `persist-actions-artifact`. The one-shot persistence command accepts only a transient GitHub Actions token plus exact artifact ID and digests. It makes one authenticated request to the fixed GitHub artifact endpoint, requires exactly one 302 to a tightly constrained short-lived read-only HTTPS Blob URL, strips authorization before the Blob request, disables environment proxies, and rejects any additional redirect. It verifies the downloaded ZIP and inner request digests, requires exactly one `paperdesk-accepted-release-request.tar.gz`, and checks the expected release prefix before any Storage call. Its distinct writer and reader managed-identity client IDs are compiled into the reviewed helper rather than selected by the caller. The older HTTP `serve` mode remains dormant and is not part of this transport.

The reviewed target runtime is App Service `PYTHON|3.12` with Always On and WebJobs enabled. The workflow first runs an isolated Python 3.12 canary with no GitHub credential, then performs two identical persistence runs to prove create-only completion and idempotent readback. The caller never stores the expiring Blob redirect: the WebJob derives it immediately before download. The transient GitHub token is passed through a mode-600 JSON settings file rather than process arguments, and every run stops the bridge and deletes all transient settings; the independent `always()` seal repeats cleanup on failure.

The fixed bridge is `paperdesk-release-registry-bridge-9c4e0d0d` in `rg-master-data-structure-sea`, while the fixed registry storage account and container remain in `rg-paperdesk-rollback-sea-20260808`; resource names and prefixes are not caller inputs. The bridge must be stopped, public access disabled, main and SCM defaults denied, FTPS disabled, and FTP/SCM basic publishing disabled before and after every attempt. The writer user-assigned identity needs create/add only; the separate reader identity needs read only. Bridge cleanup is fail-closed, removes every transient artifact coordinate, and may not delete accepted-release blobs.

Current status: this branch is ready for independent source review only; it does not approve mutation. The deterministic WebJob package and one-shot helper have not been deployed or live-canaried, and the global workflow hard stop remains. Activation still requires independent approval, immutable package bootstrap on the Python 3.12 bridge, narrow WORM-policy and WebJob run/history authorization, exact-workflow federated-credential rotation plus old-SHA denial proof, `scmIpSecurityRestrictionsUseMain=true`, ARM WebJob proof while public access stays disabled, live create/overwrite-denial canaries with retained 30-day registry evidence, and a separately reviewed PaperDesk caller pinned to the activated workflow SHA. Until those gates pass, every mutating mode exits before Azure login. Do not add a persistent secret, branch/tag workflow reference, caller-controlled Azure resource, public bridge ingress, SCM exception, Shared Key, or broad Storage role as a shortcut. The separately approved 90-day watchdog evidence store is a different container and must not change this registry's locked 30-day policy.

## Watchdog configuration

The scheduled watchdog runs only when `PAPERDESK_WATCHDOG_MODE` equals `accepted-release-deadline-v1`. It also requires:

- variable `PAPERDESK_WATCHDOG_STATE_URL`: credential-free HTTPS URL with no query, fragment, or user info;
- variable `PAPERDESK_WATCHDOG_STATE_HOST`: exact expected lower-case host;
- variable `PAPERDESK_SOURCE_REPOSITORY`: exact `owner/repository` to dispatch;
- variable `PAPERDESK_WATCHDOG_RUNBOOK_URL`: credential-free HTTPS operator runbook;
- secret `PAPERDESK_WATCHDOG_STATE_TOKEN`: read-only bearer credential for the state object;
- secret `PAPERDESK_ROLLBACK_DISPATCH_TOKEN`: fine-grained token limited to Actions write on the source repository.

Do not set the source repository's `PAPERDESK_PRODUCTION_WATCHDOG_CONFIGURED` gate until a scheduled run and an overdue-candidate drill both have retained receipts.
