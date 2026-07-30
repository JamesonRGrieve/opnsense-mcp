#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install MCP server Python dependencies into a venv on plugin install.
# OPNsense ships Python 3.11+ but not pip globally — venv isolates cleanly.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"

if [ ! -d "${VENV_DIR}" ]; then
    python3 -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${SCRIPT_DIR}/requirements.txt"
