# Offline Evaluation CLI

The public CLI exposes three commands. Evaluation consumes an existing artifact bundle and does not call a model provider.

## Synthetic demo

```powershell
$demoId = [guid]::NewGuid().ToString('N')
python -m acac --root . demo --output-dir "$env:TEMP\acac-demo-$demoId"
```

The bundled example is wholly synthetic. It has one exact authorized correction, one unauthorized/collateral proposal, and one unresolved case. The command writes JSON, Markdown, and self-contained HTML reports. Its status is intentionally `ineligible` with process exit code 2 because the unresolved case is excluded. Use a fresh output directory because report paths are create-if-absent.

## Evaluate a supplied artifact bundle

```powershell
python -m acac evaluate --bundle <bundle-directory> --config <governance.json> --output-dir <new-output-directory>
```

The bundle index binds a manifest and per-case artifacts. The coordinator validates each case's case, authorization input, review submissions, final sidecar, reference, adjudication, lifecycle events, and raw output. Only eligible cases contribute to aggregate metrics. A configured approver ID is a local declaration checked against recorded evidence; it does not authenticate a person.

The output paths are create-if-absent. Any ineligible case or structural output failure is reported explicitly and returns exit code 2. A structurally valid proposal can still contain unauthorized changes.

## Verify artifact bindings without evaluation output

```powershell
python -m acac verify-bundle --bundle <bundle-directory> --config <governance.json>
```

This command reads and verifies bundle/manifest and artifact hash bindings, then runs the coordinator's eligibility checks. It writes no report files. Matching hashes establish byte integrity for the inspected artifacts, not the truth of their contents, authorization by themselves, or identity authentication.

## Limitations

The public CLI does not submit prompts or call models. Model responses must already exist as supplied input artifacts. The v1.4 artifact-bound path corresponds to a proposal that has not been formally accepted; the v1.3.8 requirements remain the historical authoritative baseline. Synthetic review/adjudication/approval-shaped records are test fixtures, not genuine human evidence or gold labels.
