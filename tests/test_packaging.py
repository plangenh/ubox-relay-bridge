"""The HACS download is self-contained and contains no captured assets."""

import json
from pathlib import Path


def test_hacs_runtime_is_self_contained():
    root = Path(__file__).resolve().parents[1]
    component = root / "custom_components/ubox_relay"
    manifest = json.loads((component / "manifest.json").read_text())
    assert manifest["domain"] == "ubox_relay"
    assert manifest["config_flow"] is True
    assert manifest["requirements"] == []
    assert manifest["version"] == "0.2.0b2"
    assert set(manifest["dependencies"]) == {"ffmpeg", "stream"}
    assert json.loads((root / "hacs.json").read_text())["homeassistant"] == "2026.10.0"
    for filename in (
        "__init__.py",
        "camera.py",
        "cloud.py",
        "config_flow.py",
        "const.py",
        "diagnostics.py",
        "http.py",
        "protocol.py",
        "stream.py",
        "services.yaml",
        "strings.json",
        "translations/de.json",
        "translations/en.json",
        "brand/icon.png",
    ):
        assert (component / filename).is_file(), filename
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        assert (component / name).read_bytes() == (root / name).read_bytes()
    # Runtime must not invoke/download the old Go executable or its HA adapter.
    combined = "\n".join(p.read_text() for p in component.glob("*.py"))
    assert "ubox-relay-bridge" not in combined
    assert "core.config_entries" not in combined


def test_translations_and_service_definitions():
    component = Path(__file__).resolve().parents[1] / "custom_components/ubox_relay"
    english = json.loads((component / "strings.json").read_text())
    for language in ("en", "de"):
        translated = json.loads(
            (component / f"translations/{language}.json").read_text()
        )
        assert translated.keys() == english.keys()
        assert set(translated["services"]) == {"get_stream_url", "rotate_stream_token"}
    data = (component / "services.yaml").read_text()
    assert "get_stream_url:" in data
    assert "rotate_stream_token:" in data
