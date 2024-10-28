#!/bin/sh

set -ex

# Redirect https://gitlab.suse.de to localhost
echo "127.0.0.1 gitlab.suse.de" >> /etc/hosts

priv_key="/usr/share/pki/trust/anchors/server.crt"
openssl req -nodes -x509 -newkey rsa:4096 -keyout $priv_key -out $priv_key -days 365 -subj '/CN=gitlab.suse.de'
update-ca-certificates

python3 webserver.py

