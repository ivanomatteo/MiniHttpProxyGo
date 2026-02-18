#!/bin/bash

set -euo pipefail

USER_PROXY='mini-proxy'

# Crea l'utente "proxy" come utente di sistema (-r), senza home (-M) e senza shell di login
sudo useradd -r -M -s /usr/sbin/nologin "$USER_PROXY"

# Crea il gruppo "proxy" se non esiste già
sudo groupadd -r "$USER_PROXY" || true

# Associa l'utente al gruppo
sudo usermod -a -G "$USER_PROXY" "$USER_PROXY"

# Crea la directory di lavoro per il proxy
sudo mkdir -p /opt/mini-proxy

# Cambia proprietà alla directory e al contenuto
sudo chown -R "$USER_PROXY":"$USER_PROXY" /opt/mini-proxy
sudo chmod 750 /opt/mini-proxy


cp mini-proxy /opt/mini-proxy/ 
cp config.json /opt/mini-proxy/ 

chown -R "$USER_PROXY":"$USER_PROXY" /opt/mini-proxy/ 

cp mini-proxy.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable mini-proxy
systemctl start mini-proxy

systemctl status mini-proxy

