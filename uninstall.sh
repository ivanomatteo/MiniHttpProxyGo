#!/bin/bash

set -euo pipefail

SERVICE_NAME='mini-proxy'
USER_PROXY='mini-proxy'
INSTALL_DIR='/opt/mini-proxy'
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

PURGE=false
if [[ "${1:-}" == '--purge' ]]; then
    PURGE=true
elif [[ $# -gt 0 ]]; then
    echo "Uso: $0 [--purge]" >&2
    exit 2
fi

if [[ $EUID -ne 0 ]]; then
    echo "Errore: eseguire questo script come root (ad esempio: sudo $0)." >&2
    exit 1
fi

echo "Arresto e disabilitazione del servizio ${SERVICE_NAME}..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

echo "Rimozione del servizio systemd..."
rm -f "$SERVICE_FILE"
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

if [[ $PURGE == true ]]; then
    echo "Rimozione di ${INSTALL_DIR}, utente e gruppo ${USER_PROXY}..."
    rm -rf "$INSTALL_DIR"

    if id "$USER_PROXY" &>/dev/null; then
        userdel "$USER_PROXY"
    fi

    if getent group "$USER_PROXY" &>/dev/null; then
        groupdel "$USER_PROXY"
    fi
else
    echo "La directory ${INSTALL_DIR} e l'utente ${USER_PROXY} non sono stati rimossi."
    echo "Per eliminarli definitivamente, eseguire: sudo $0 --purge"
fi

echo "Disinstallazione completata."
