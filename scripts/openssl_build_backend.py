# TEMPORARY: remove before merging into dev, and restore `build-backend = "maturin"` in pyproject.toml.
# Builds the vendored OpenSSL before maturin runs, so unreleased 1.0 installs from a git source with just `uv sync`.
import subprocess
import sys
from pathlib import Path

import maturin
from maturin import *  # re-exports maturin's other PEP 517 hooks

BUILD_OPENSSL = Path(__file__).resolve().parent / "build-openssl.sh"


def _build_openssl():
    # the script returns immediately once OpenSSL is built
    subprocess.run(["bash", str(BUILD_OPENSSL)], check=True, stdout=sys.stderr)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _build_openssl()
    return maturin.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    _build_openssl()
    return maturin.build_editable(wheel_directory, config_settings, metadata_directory)
