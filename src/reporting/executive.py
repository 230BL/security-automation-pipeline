from __future__ import annotations

from typing import Any


def build_manifest_summary(manifest: Any) -> dict[str, Any]:
    """Build a minimal summary dict for reporting templates."""
    try:
        org = getattr(manifest, "organization", "")
        name = getattr(manifest, "assessment_name", "")
        asset_classes = getattr(manifest, "asset_classes", [])
        envs = sorted(
            {
                getattr(ac, "environment", "")
                for ac in asset_classes
                if getattr(ac, "environment", "")
            }
        )
        return {
            "organization": org,
            "assessment_name": name,
            "asset_class_count": len(asset_classes) if isinstance(asset_classes, list) else 0,
            "environments": ", ".join(envs) if envs else "",
        }
    except Exception:
        return {
            "organization": "",
            "assessment_name": "",
            "asset_class_count": 0,
            "environments": "",
        }
