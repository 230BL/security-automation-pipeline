# Security Automation Pipeline

Gated, modular vulnerability-management pipeline with governance-first design.

## Quick Start (Lab)

```bash
# Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Run unit tests
pytest -q

# Start platform services (OpenSearch + DefectDojo)
docker compose -f compose/docker-compose.yml --env-file compose/env/.env.example up -d

# Validate governance gate only
python scripts/run_pipeline.py --profile config/profiles/lab_poc.yml --dry-run

# Run pipeline (lab profile)
python scripts/run_pipeline.py --profile config/profiles/lab_poc.yml
```

## Architecture

```
[Signed Scope + Manifest + Allowlist + Window]
                    |
                    v
           [Authorization Gate]
                    |
                    v
             [Python Orchestrator]
                    |
    ------------------------------------------------
    |              |              |              |
    v              v              v              v
[Inventory]  [Passive Disc]  [Auth Vuln]  [Config Audit]
    \              |             /              /
     \             |            /              /
      v            v           v              v
                [Normalizer + Schema Validation]
                          |
                          v
               [Risk Scoring + Dedup]
                          |
          ----------------------------------
          |                                |
          v                                v
  [DefectDojo Findings]         [OpenSearch Dashboards]
          |                                |
          v                                v
 [Tickets / SLA / Retest]      [Coverage / Trends]
          |
          v
 [Executive + Technical Reports]
```

## Key Commands

| Command | Purpose |
|---------|---------|
| `make install-dev` | Install dev dependencies |
| `make test` | Run unit tests |
| `make up` | Start Docker services |
| `make verify-scope` | Verify scope signature |
| `make run-pipeline` | Execute pipeline |
| `make down` | Stop services |
| `make clean` | Remove cached artifacts |

## Project Structure

See `compose/`, `config/`, `scope/`, `src/`, `scripts/`, `ansible/`, `policy/`, `reports/`, `tests/`.
