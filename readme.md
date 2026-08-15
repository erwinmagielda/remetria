# Remetria

Remetria is a Windows patch-prioritisation analysis tool built for Kolektria scan outputs.

Kolektria collects Windows update-state evidence from authorised hosts. Remetria analyses a controlled corpus of Kolektria `scan.json` files and compares remediation ranking behaviour across three prioritisation methods:

1. CVSS-only ranking
2. MSRC severity-only ranking
3. Context-aware ranking

The project is part of the dissertation **Context-Aware Vulnerability Prioritisation for Windows Patch Remediation**.

## Purpose

Remetria is designed to assess how missing Windows KB updates are prioritised when different ranking methods are applied to the same scan evidence.

The tool does not scan Windows systems directly. It reads Kolektria JSON outputs, normalises the KB and CVE evidence, builds remediation candidate tables, applies prioritisation logic, and exports analysis reports and supporting tables.