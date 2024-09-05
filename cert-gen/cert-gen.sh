#!/bin/bash

script_dir=$(dirname "$(readlink -f "$0")")

if [ -z "$1" ]; then
  target_dir=$(pwd)
else
  target_dir="$1"
fi

mkdir -p "$target_dir/certs"
cd "$target_dir/certs"

rm -f *.pem

openssl genpkey -algorithm RSA -out ca-key.pem
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca.pem -subj "/CN=flare" -config "$script_dir/ca-cert.conf" -extensions v3_ca
openssl genpkey -algorithm RSA -out server-key.pem
openssl req -new -key server-key.pem -out server.pem -subj "/CN=flare"
openssl x509 -req -in server.pem -CA ca.pem -CAkey ca-key.pem -out server.pem -days 3650 -extfile "$script_dir/server-cert.conf" -extensions v3_req
openssl genpkey -algorithm RSA -out client-key.pem
openssl req -new -key client-key.pem -out client.pem -subj "/CN=flare"
openssl x509 -req -in client.pem -CA ca.pem -CAkey ca-key.pem -out client.pem -days 3650 -extfile "$script_dir/client-cert.conf" -extensions v3_req

rm ca-key.pem

chmod 400 *
