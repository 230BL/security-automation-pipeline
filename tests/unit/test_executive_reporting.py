from __future__ import annotations

from types import SimpleNamespace

from src.reporting.executive import build_manifest_summary


def test_build_manifest_summary_returns_expected_fields() -> None:
    manifest = SimpleNamespace(
        organization="Lab Org",
        assessment_name="Quarterly Validation",
        asset_classes=[
            SimpleNamespace(environment="prod"),
            SimpleNamespace(environment="lab"),
            SimpleNamespace(environment="prod"),
            SimpleNamespace(environment=""),
        ],
    )

    summary = build_manifest_summary(manifest)

    assert summary == {
        "organization": "Lab Org",
        "assessment_name": "Quarterly Validation",
        "asset_class_count": 4,
        "environments": "lab, prod",
    }


def test_build_manifest_summary_non_list_asset_classes_returns_zero_count() -> None:
    manifest = SimpleNamespace(
        organization="Org",
        assessment_name="Assessment",
        asset_classes="not-a-list",
    )

    summary = build_manifest_summary(manifest)

    assert summary == {
        "organization": "Org",
        "assessment_name": "Assessment",
        "asset_class_count": 0,
        "environments": "",
    }


def test_build_manifest_summary_missing_attributes_falls_back_to_defaults() -> None:
    manifest = SimpleNamespace()

    summary = build_manifest_summary(manifest)

    assert summary == {
        "organization": "",
        "assessment_name": "",
        "asset_class_count": 0,
        "environments": "",
    }


def test_build_manifest_summary_ignores_asset_classes_without_environment() -> None:
    manifest = SimpleNamespace(
        organization="Org",
        assessment_name="Assessment",
        asset_classes=[
            SimpleNamespace(environment="dev"),
            SimpleNamespace(),
            SimpleNamespace(environment=""),
            SimpleNamespace(environment="qa"),
        ],
    )

    summary = build_manifest_summary(manifest)

    assert summary["asset_class_count"] == 4
    assert summary["environments"] == "dev, qa"


class ExplodingManifest:
    @property
    def organization(self) -> str:
        raise RuntimeError("boom")


def test_build_manifest_summary_returns_safe_defaults_on_exception() -> None:
    summary = build_manifest_summary(ExplodingManifest())

    assert summary == {
        "organization": "",
        "assessment_name": "",
        "asset_class_count": 0,
        "environments": "",
    }
