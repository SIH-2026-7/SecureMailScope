#!/bin/sh
set -eu
# Linux only: run in the isolated lab network namespace, never on an unrelated interface.
NAME=${1:-hardened}
INTERFACE=${INTERFACE:-lo}
mkdir -p captures
exec tcpdump -i "$INTERFACE" -s 0 -w "captures/scenario_${NAME}.pcap" 'tcp and (port 25 or port 143 or port 110 or port 587 or port 465 or port 993 or port 995)'
