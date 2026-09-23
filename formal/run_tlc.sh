#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
: "${TLA2TOOLS_JAR:?Set TLA2TOOLS_JAR to tla2tools.jar}"
java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC -deadlock -config Ratchet.cfg Ratchet.tla
