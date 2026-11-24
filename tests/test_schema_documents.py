import json
from pathlib import Path


def test_packaged_json_schemas_are_valid_documents() -> None:
    schema_dir = Path(__file__).parents[1] / "src" / "plcsec" / "schemas"
    expected = {
        "plcsec.asset-inventory.v1.schema.json": "plcsec.asset-inventory.v1",
        "plcsec.site-profile.v1.schema.json": "plcsec.site-profile.v1",
        "plcsec.firmware-analysis.v1.schema.json": "plcsec.firmware-analysis.v1",
        "plcsec.artifact-signature.v1.schema.json": "plcsec.artifact-signature.v1",
        "plcsec.baseline-approval.v1.schema.json": "plcsec.baseline-approval.v1",
        "plcsec.opcua-certificate-audit.v1.schema.json": "plcsec.opcua-certificate-audit.v1",
        "plcsec.advisories.v1.schema.json": "plcsec.advisories.v1",
    }
    for filename, schema_id in expected.items():
        document = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["properties"]["schema"]["const"] == schema_id
        assert "required" in document


def test_schema_files_are_included_by_package_data_configuration() -> None:
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'schemas/*.json' in pyproject
