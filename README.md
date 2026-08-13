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

## Pinning model

Verifier scripts are pinned inside reusable workflows to an earlier immutable full commit SHA. PaperDesk callers pin the reusable workflow itself to a later full commit SHA. This two-commit update process avoids a circular self-reference:

1. merge and test verifier script changes;
2. update the workflow's internal script checkout to that full SHA and merge;
3. update the PaperDesk caller to the new workflow full SHA;
4. update the Azure federated-identity subject only after review so it requires that exact `job_workflow_ref` and the protected production environment.

Never call a branch or tag from a production workflow. Never place application bytes or evidence in this public repository.

## Local verification

```bash
python -m unittest discover -s tests -v
python -m py_compile scripts/verify_candidate.py scripts/check_deadline.py
```

## Watchdog configuration

The scheduled watchdog runs only when `PAPERDESK_WATCHDOG_MODE` equals `accepted-release-deadline-v1`. It also requires:

- variable `PAPERDESK_WATCHDOG_STATE_URL`: credential-free HTTPS URL with no query, fragment, or user info;
- variable `PAPERDESK_WATCHDOG_STATE_HOST`: exact expected lower-case host;
- variable `PAPERDESK_SOURCE_REPOSITORY`: exact `owner/repository` to dispatch;
- variable `PAPERDESK_WATCHDOG_RUNBOOK_URL`: credential-free HTTPS operator runbook;
- secret `PAPERDESK_WATCHDOG_STATE_TOKEN`: read-only bearer credential for the state object;
- secret `PAPERDESK_ROLLBACK_DISPATCH_TOKEN`: fine-grained token limited to Actions write on the source repository.

Do not set the source repository's `PAPERDESK_PRODUCTION_WATCHDOG_CONFIGURED` gate until a scheduled run and an overdue-candidate drill both have retained receipts.
