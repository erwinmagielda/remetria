# Remetria

Remetria is a Windows patch-remediation analysis tool. It consumes Kolektria scan JSON evidence, enriches observed CVEs with advisory and CVSS metadata, ranks missing KB candidates using CVSS-only, MSRC-only and CPRI methods, and exports comparison evidence for ranking evaluation.

CPRI means Contextual Patch Remediation Index.

## Purpose

Remetria supports repeatable comparison of three Windows update prioritisation methods:

| Method | Purpose |
|:---|:---|
| CVSS-only | Ranks missing KB candidates using CVSS-derived severity evidence. |
| MSRC-only | Ranks missing KB candidates using Microsoft advisory severity and exploit/disclosure evidence. |
| CPRI | Ranks missing KB candidates using enriched vulnerability evidence and local remediation context. |

## Workflow

Place Kolektria scan JSON files in:

```text
data\runtime
```

Run Remetria:

```powershell
python -m remetria.analyser
```

Select:

```text
1. Run Analysis
```

Remetria creates one timestamped output folder:

```text
results\analysis_YYYYMMDD_HHMMSS
```

## Output

Each analysis run exports:

```text
results\analysis_YYYYMMDD_HHMMSS
├── json
│   └── remetria_analysis.json
├── tables
│   ├── scan_summary.csv
│   ├── cve_rows.csv
│   ├── kb_candidates.csv
│   ├── cve_enrichment.csv
│   ├── kb_candidates_enriched.csv
│   ├── ranking_comparison.csv
│   └── evaluation_metrics.csv
└── reports
    └── remetria_report.md
```

The Markdown report is the main readable output. The JSON and CSV files provide the same analysis evidence in machine-readable and tabular form.

## Clear Artefacts

Select:

```text
2. Clear Artefacts
```

This clears runtime input files, generated analysis folders and temporary development artefacts. It preserves deliberate archive folders, build scripts and executable output.

## Scope

Remetria performs analysis and reporting. It does not install patches, run exploit tests, scan unauthorised systems or perform production remediation.

CVSS-only and MSRC-only are comparison baselines. CPRI is the context-aware ranking method used by this workflow.