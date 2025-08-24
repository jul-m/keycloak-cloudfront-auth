#!/usr/bin/env bash
set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(dirname "$SCRIPTDIR")"
DISPLAY_NAME="$0"
if [ -n "${PARENT_CMD:-}" ]; then
  DISPLAY_NAME="$PARENT_CMD"
elif [ "$REPO_ROOT" = "$(pwd)" ]; then
  DISPLAY_NAME="./scripts/$(basename "$0")"
fi

usage() {
  cat <<EOF
Usage: $DISPLAY_NAME <stack> [options] [KEYCLOAK_VERSION] [-- extra docker-compose args]

Stacks:
  demo       Run the demo stack (docker/demo/compose.yml)
  dev-tests  Run the dev-tests stack (docker/dev-tests/compose.yml)

Options:
  -d, --detach    Pass -d to 'docker compose up' (detached). The script always
                  runs 'docker compose up' and will restart containers if compose
                  didn't change anything but containers were already running.
  -h, --help      Show this help

Examples:
  $DISPLAY_NAME dev-tests 26.3
  $DISPLAY_NAME dev-tests -d 26.3
  $DISPLAY_NAME demo --build
EOF
  exit 2
}

if [ "$#" -lt 1 ]; then
  usage
fi

case "$1" in
  -h|--help|help)
    usage
    ;;
  demo)
    TARGET_COMPOSE_FILE="$REPO_ROOT/docker/demo/compose.yml"
    shift
    ;;
  dev-tests)
    TARGET_COMPOSE_FILE="$REPO_ROOT/docker/dev-tests/compose.yml"
    shift
    ;;
  *)
    echo "Unknown stack: $1" >&2
    usage
    ;;
esac

# Parse remaining args: accept optional -d/--detach and an optional KEYCLOAK_VERSION
DETACH=false
KCA_KC_VERSION=""
COMPOSE_ARGS=()
while [ $# -gt 0 ]; do
  arg="$1"; shift
  case "$arg" in
    -d|--detach)
      DETACH=true
      ;;
    -h|--help|help)
      usage
      ;;
    --)
      # all remaining args are forwarded
      while [ $# -gt 0 ]; do
        COMPOSE_ARGS+=("$1")
        shift
      done
      ;;
    *)
      if { [[ "$arg" =~ ^([0-9]+)(\.[0-9]+)?$ ]] || [ "$arg" = "all" ]; } && [ -z "$KCA_KC_VERSION" ]; then
        KCA_KC_VERSION="$arg"
      else
        COMPOSE_ARGS+=("$arg")
      fi
      ;;
  esac
done

# Build docker compose command
CMD=(docker compose -f "$TARGET_COMPOSE_FILE" up)
if [ "$DETACH" = true ]; then
  CMD+=("-d")
fi
if [ ${#COMPOSE_ARGS[@]} -gt 0 ]; then
  CMD+=("${COMPOSE_ARGS[@]}")
fi

# Export KCA_KC_VERSION to environment for the compose process if provided
if [ -n "$KCA_KC_VERSION" ]; then
  export KCA_KC_VERSION
  echo "Using KCA_KC_VERSION=$KCA_KC_VERSION"
fi

if [ "$DETACH" = false ]; then
  # Foreground mode: run docker compose up and stream output directly.
  echo "Running: ${CMD[*]}"
  set +e
  "${CMD[@]}"
  rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    echo "[ERROR] docker-run failed (exit code $rc)."
    exit $rc
  fi
else
  # Detached mode: preserve previous behaviour (capture output, compare ids, restart if needed)
  # Capture existing container IDs for this compose file before running
  set +e
  EXISTING_IDS=$(docker compose -f "$TARGET_COMPOSE_FILE" ps -q 2>/dev/null || true)
  set -e

  # Are all existing containers running right now?
  ALL_RUNNING=true
  if [ -n "$EXISTING_IDS" ]; then
    for id in $EXISTING_IDS; do
      r=$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || echo false)
      if [ "$r" != "true" ]; then
        ALL_RUNNING=false
        break
      fi
    done
  fi

  echo "Running: ${CMD[*]}"
  set +e
  OUTPUT=$("${CMD[@]}" 2>&1 || true)
  rc=$?
  set -e

  # Capture container IDs after compose up
  set +e
  NEW_IDS=$(docker compose -f "$TARGET_COMPOSE_FILE" ps -q 2>/dev/null || true)
  set -e

  # Normalize lists for comparison
  EXISTING_SORT=$(printf "%s\n" $EXISTING_IDS | sort | tr -d '\r' || true)
  NEW_SORT=$(printf "%s\n" $NEW_IDS | sort | tr -d '\r' || true)

  RESTARTED=false
  # If compose succeeded but didn't create/start new containers (ids identical)
  # and the previous containers were already running, restart them to get a clean state.
  if [ $rc -eq 0 ] && [ -n "$EXISTING_IDS" ] && [ "$EXISTING_SORT" = "$NEW_SORT" ] && [ "$ALL_RUNNING" = true ]; then
    echo "Compose reported no changes and containers were already running — restarting containers."
    set +e
    docker compose -f "$TARGET_COMPOSE_FILE" restart
    restart_rc=$?
    set -e
    RESTARTED=true
    if [ $restart_rc -ne 0 ]; then
      echo "[ERROR] Failed to restart containers (exit code $restart_rc)."
      echo "$OUTPUT"
      exit $restart_rc
    fi
  fi

  # If compose succeeded and we didn't do a restart, show the compose output
  if [ $rc -eq 0 ] && [ "$RESTARTED" = false ]; then
    echo "$OUTPUT"
  fi

  if [ $rc -ne 0 ]; then
    echo "$OUTPUT"
    echo "[ERROR] docker-run failed (exit code $rc)."
    exit $rc
  fi
fi

exit 0
