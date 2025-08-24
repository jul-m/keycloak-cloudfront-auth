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
Usage: $DISPLAY_NAME <stack> [sub-command] [options] [version-token] [-- extra docker-compose args]

Stacks:
  demo       Run the demo stack (docker/demo/compose.yml).
             Optional version-token sets the demo image tag and will be exported
             to the compose environment as VERSION (used by docker/demo/compose.yml).
  dev-tests  Run the dev-tests stack (docker/dev-tests/compose.yml).
             Optional version-token sets the Keycloak version and will be exported
             as KCA_KC_VERSION (used to fetch keycloak-config-cli when needed).

Sub-commands:
  up         Start the stack (default)
  down       Tear down the stack (runs 'docker compose down -v --remove-orphans')

Options (for 'up'):
  -d, --detach    Pass -d to 'docker compose up' (detached). The script will
                  restart containers if compose didn't change anything but
                  containers were already running.
  --vars VAR=val  Pass one or more environment variable assignments to export
                  for the compose run. Example:
                  --vars KCA_PROVIDER_JAR_NAME=build.jar KCA_KC_ADMIN_USER=admin
  -h, --help      Show this help

Examples:
  $DISPLAY_NAME dev-tests up 26.3
  $DISPLAY_NAME dev-tests up -d 26.3
  $DISPLAY_NAME dev-tests down
  $DISPLAY_NAME demo up 1.2.3
  $DISPLAY_NAME demo up -d 1.2.3 --build
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
# Accept optional sub-command (up/down). Default to up.
MODE="up"
if [ "$#" -gt 0 ] && ( [ "$1" = "up" ] || [ "$1" = "down" ] ); then
  MODE="$1"
  shift
fi

# Parse remaining args: accept optional -d/--detach and an optional version token
# For the demo stack this token is the demo image tag and will be exported as VERSION.
# For the dev-tests stack this token is a Keycloak version and will be exported as KCA_KC_VERSION.
DETACH=false
KCA_KC_VERSION=""
VERSION=""
COMPOSE_ARGS=()
# Store explicit variable assignments provided via --vars
EXTRA_VARS=()
while [ $# -gt 0 ]; do
  arg="$1"; shift
  case "$arg" in
    -d|--detach)
      DETACH=true
      ;;
    --vars)
      # Collect following tokens that look like NAME=VALUE
      while [ $# -gt 0 ]; do
        next="$1"
        # valid var assignment: contains '=' and starts with a letter or underscore
        if [[ "$next" == *=* && "$next" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
          EXTRA_VARS+=("$next")
          shift
        else
          break
        fi
      done
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
      # If the token does NOT start with '-' and we don't already have a version token,
      # treat it as the version token. Otherwise forward to compose args.
      if [[ "$arg" != -* ]] && [ -z "$KCA_KC_VERSION" ] && [ -z "$VERSION" ]; then
        # If we're running the demo stack, set VERSION (demo image tag). Otherwise set KCA_KC_VERSION.
        if [ "$TARGET_COMPOSE_FILE" = "$REPO_ROOT/docker/demo/compose.yml" ]; then
          VERSION="$arg"
        else
          KCA_KC_VERSION="$arg"
        fi
      else
        COMPOSE_ARGS+=("$arg")
      fi
      ;;
  esac
done

# If mode is down, run docker compose down now
if [ "$MODE" = "down" ]; then
  # Print the compose down command we are about to run. Avoid expanding
  # COMPOSE_ARGS when it's empty to remain safe under 'set -u'.
  if [ ${#COMPOSE_ARGS[@]} -gt 0 ]; then
    echo "Tearing down stack using: docker compose -f $TARGET_COMPOSE_FILE down -v --remove-orphans ${COMPOSE_ARGS[*]}"
  else
    echo "Tearing down stack using: docker compose -f $TARGET_COMPOSE_FILE down -v --remove-orphans"
  fi
  set +e
  docker compose -f "$TARGET_COMPOSE_FILE" down -v --remove-orphans ${COMPOSE_ARGS[@]:-}
  rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    echo "[ERROR] docker-compose down failed (exit code $rc)."
    exit $rc
  fi
  exit 0
fi

# Build docker compose command
CMD=(docker compose -f "$TARGET_COMPOSE_FILE" up)
if [ "$DETACH" = true ]; then
  CMD+=("-d")
fi
if [ ${#COMPOSE_ARGS[@]} -gt 0 ]; then
  CMD+=("${COMPOSE_ARGS[@]}")
fi

# In CI (GitHub Actions) prefer quiet pulls to avoid noisy progress bars
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  # Add --quiet-pull unless already present in the command
  skip_quiet=0
  for a in "${CMD[@]}"; do
    if [ "$a" = "--quiet-pull" ]; then
      skip_quiet=1
      break
    fi
  done
  if [ $skip_quiet -eq 0 ]; then
    CMD+=("--quiet-pull")
  fi
fi

# Export any extra VAR=VALUE provided via --vars
if [ ${#EXTRA_VARS[@]} -gt 0 ]; then
  echo "Exporting variables from --vars: ${EXTRA_VARS[*]}"
  for pair in "${EXTRA_VARS[@]}"; do
    # split NAME=VALUE
    name="${pair%%=*}"
    value="${pair#*=}"
    export "$name=$value"
  done
fi

# Export VERSION or KCA_KC_VERSION to environment for the compose process if provided
if [ -n "$VERSION" ]; then
  export VERSION
  echo "Using VERSION=$VERSION"
fi

if [ -n "$KCA_KC_VERSION" ]; then
  export KCA_KC_VERSION
  echo "Using KCA_KC_VERSION=$KCA_KC_VERSION"

  if [ "$TARGET_COMPOSE_FILE" = "$REPO_ROOT/docker/dev-tests/compose.yml" ]; then
    # Ensure keycloak-config-cli jar is available in lib/ (download if needed)
    echo "Fetching keycloak-config-cli for Keycloak $KCA_KC_VERSION into lib/... if missing"
    scripts/fetch-kc-config-cli.sh "$KCA_KC_VERSION"
  fi
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
