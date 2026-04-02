## Scope folder

This pipeline is **governance-first**. Nothing runs unless the scope gate passes.

### Files

- `scope_manifest.yml`: signed scope manifest (copy from `scope_manifest.example.yml`)
- `allowlist.txt`: approved targets (copy from `allowlist.example.txt`)
- `maintenance_windows.yml`: optional maintenance window catalog
- `approved_signers.gpg`: keyring of authorized signing keys
- `*.sig`: detached signatures for signed scope artifacts

### Lab mode

Lab mode can be enabled via `config/orchestrator.yml` (`lab_mode: true`). When enabled, the
pipeline will allow running with unsigned scope artifacts but will **always** log warnings.
Do not use lab mode for production targets.
