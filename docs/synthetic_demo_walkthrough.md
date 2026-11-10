# Synthetic CLI Demonstration Walkthrough

This walkthrough uses only `examples/synthetic_v14_bundle/`. It does not read private review records, gold data, or model responses.

From the repository root, create a unique output directory and run:

```powershell
$demoId = [guid]::NewGuid().ToString('N')
$demoOut = Join-Path $env:TEMP "acac-demo-$demoId"
python -m acac --root . demo --output-dir $demoOut
```

The expected summary is three scheduled cases, two included and one excluded, with zero structural failures. The overall status is `ineligible`; exit code 2 is intentional because one synthetic case has unresolved authorization. The command still writes JSON, Markdown, and HTML explanations.

Open the `.html` path printed in the JSON output. Review the case-level outcomes, edit decisions, preservation checks, exclusion reason, and artifact-hash provenance. The HTML report is self-contained. Hashes show which synthetic bytes were checked; they do not authenticate a person or prove the source's truth.

Do not describe this synthetic demonstration as a model benchmark, human adjudication, approved gold, or formal grading authorization.
