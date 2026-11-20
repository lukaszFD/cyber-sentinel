#!/bin/bash
exec "$(dirname "$0")/pg_tunnel.sh" dev "$@"
