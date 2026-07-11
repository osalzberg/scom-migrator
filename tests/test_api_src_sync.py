"""Guard test: the api/ and src/ copies of scom_migrator must stay identical.

The web app (Azure Functions) runs ``api/scom_migrator/`` while the CLI and the
test suite run ``src/scom_migrator/``. They are deployed as separate,
self-contained copies, so this test fails loudly if they ever drift again —
preventing a bug from being fixed in one copy but not the other (which is how
``parser.py`` and ``generator.py`` previously diverged).
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
API_PKG = REPO_ROOT / "api" / "scom_migrator"
SRC_PKG = REPO_ROOT / "src" / "scom_migrator"

PACKAGE_FILES = sorted(p.name for p in SRC_PKG.glob("*.py"))


def test_same_set_of_modules():
    """Both copies expose exactly the same set of Python modules."""
    api_mods = {p.name for p in API_PKG.glob("*.py")}
    src_mods = {p.name for p in SRC_PKG.glob("*.py")}
    assert api_mods == src_mods, (
        "api/ and src/ scom_migrator contain different modules: "
        f"only in api={api_mods - src_mods}, only in src={src_mods - api_mods}"
    )


@pytest.mark.parametrize("filename", PACKAGE_FILES)
def test_api_and_src_package_files_match(filename):
    """Every shared module must be byte-for-byte identical across both copies."""
    api_file = API_PKG / filename
    src_file = SRC_PKG / filename
    assert api_file.exists(), f"Missing api copy: api/scom_migrator/{filename}"
    assert src_file.read_text(encoding="utf-8") == api_file.read_text(encoding="utf-8"), (
        f"api/scom_migrator/{filename} and src/scom_migrator/{filename} have drifted. "
        "Apply changes to BOTH copies — they are deployed separately."
    )
