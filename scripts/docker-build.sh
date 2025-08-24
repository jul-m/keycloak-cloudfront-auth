#!/usr/bin/env bash
set -euo pipefail

# Ensure arrays used later are defined to avoid "unbound variable" with set -u
PROGRESS_ARG=()
PLATFORM_ARG=()

# Friendly display name for usage. Prefer PARENT_CMD when provided by a wrapper
# so delegated help shows how the wrapper was invoked. Otherwise show a
# relative './scripts/docker-build.sh' when running from repo root.
SCRIPTDIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(dirname "$SCRIPTDIR")"
DISPLAY_NAME="$0"
if [ -n "${PARENT_CMD:-}" ]; then
  DISPLAY_NAME="$PARENT_CMD"
elif [ "$REPO_ROOT" = "$(pwd)" ]; then
  DISPLAY_NAME="./scripts/$(basename "$0")"
fi

# If running under GitHub Actions, prefer plain progress output to avoid
# interactive progress bars which don't render well in Actions logs.
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  export DOCKER_BUILDKIT=1
  export BUILDKIT_PROGRESS=plain
  PROGRESS_ARG=(--progress=plain)
else
  PROGRESS_ARG=()
fi

usage() {
  cat <<EOF
Keycloak CloudFront Auth - Build Tools Docker Images

Usage: $DISPLAY_NAME <subcommand> <args>
Subcommands: demo, cf-auth-sim, help

$DISPLAY_NAME cf-auth-sim [<tags>...]
  Build the CloudFront auth simulator image (docker/cf-auth-sim).
  Optional <tags> list (space-separated). Default: "latest".
  Optional: append a separator `--` followed by any extra arguments to pass
  directly to 'docker build'. Example: -- --platform linux/amd64,linux/arm64 --pull

$DISPLAY_NAME demo <KC_VERSION> [<tags>...]
  Build preconfigured Keycloak image for keycloak-cloudfront-auth Demo (docker/demo/Dockerfile).
  <KC_VERSION> must be in format XX.Y and provider version build must exist in dist/. Example: "26.3"
  Optional <tags> list (space-separated). Default: "latest".
  Optional: append a separator `--` followed by any extra arguments to pass
  directly to 'docker build'. Example: -- --platform linux/amd64,linux/arm64 --pull

$DISPLAY_NAME help
    Show this help (also available as -h or --help)

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
  
  cf-auth-sim)
    shift || true
    # Remaining args are optional tags (space-separated). To pass extra
    # arguments to `docker build`, append a `--` separator and list them.
    # Example: cf-auth-sim tag1 tag2 -- --platform linux/amd64,linux/arm64 --pull
    DOCKER_EXTRA_ARGS=()
    tags=()
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--" ]; then
        shift || true
        DOCKER_EXTRA_ARGS=("$@")
        break
      fi
      tags+=("$1")
      shift || true
    done
    if [ "${#tags[@]}" -eq 0 ]; then
      tags=("latest")
    fi

    echo "Building docker image 'keycloak-cloudfront-auth-simulator' with tags: ${tags[*]}"
    if [ "${#DOCKER_EXTRA_ARGS[@]}" -gt 0 ]; then
      echo "  docker build extra args: ${DOCKER_EXTRA_ARGS[*]}"
    fi

    build_tag_args=()
    for t in "${tags[@]}"; do
      # Normalize empty tag
      if [ -z "$t" ]; then
        t=latest
      fi
      build_tag_args+=( -t "keycloak-cloudfront-auth-simulator:${t}" )
    done

  docker_args=("${build_tag_args[@]}")
  if [ "${#PROGRESS_ARG[@]}" -gt 0 ]; then
    docker_args+=("${PROGRESS_ARG[@]}")
  fi
  if [ "${#DOCKER_EXTRA_ARGS[@]}" -gt 0 ]; then
    docker_args+=("${DOCKER_EXTRA_ARGS[@]}")
  fi
  docker build "${docker_args[@]}" -f docker/cf-auth-sim/Dockerfile docker/cf-auth-sim
    ;;
  
  demo)
    shift
    KC_VERSION="${1:-}"
    if [ -z "$KC_VERSION" ]; then
      echo "demo requires a KC_VERSION argument." >&2
      usage
    fi

    # consume KC_VERSION so remaining args are optional tags
    shift || true

    # Remaining args are optional tags (space-separated). To pass extra
    # arguments to `docker build`, append a `--` separator and list them.
    # Example: demo 26.3 tag1 -- --platform linux/amd64,linux/arm64 --pull
    DOCKER_EXTRA_ARGS=()
    tags=()
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--" ]; then
        shift || true
        DOCKER_EXTRA_ARGS=("$@")
        break
      fi
      tags+=("$1")
      shift || true
    done
    if [ "${#tags[@]}" -eq 0 ]; then
      tags=("latest")
    fi

    if ! [[ "$KC_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
      echo "Invalid Keycloak version format: '$KC_VERSION' (expected XX.Y, e.g. 26.3)" >&2
      usage
    fi

    DIST_DIR="dist"
    if [ ! -d "$DIST_DIR" ]; then
      echo "Directory '$DIST_DIR' not found. Build artifacts must be in $DIST_DIR" >&2
      exit 1
    fi

    # Find matching provider JAR in dist (portable: glob with nullglob)
    if shopt -q nullglob >/dev/null 2>&1; then
      NULLGLOB_WAS_SET=1
    else
      NULLGLOB_WAS_SET=0
      shopt -s nullglob
    fi
    matches=( "$DIST_DIR"/keycloak-cloudfront-auth-*-KC${KC_VERSION}*.jar )
    if [ "$NULLGLOB_WAS_SET" -eq 0 ]; then
      shopt -u nullglob
    fi

    if [ "${#matches[@]}" -eq 0 ]; then
      echo "No provider JAR found in $DIST_DIR matching Keycloak $KC_VERSION" >&2
      echo "Searched pattern: keycloak-cloudfront-auth-*-KC${KC_VERSION}*.jar" >&2
      echo "Files in $DIST_DIR:" >&2
      ls -1 "$DIST_DIR" || true
      exit 1
    fi
    if [ "${#matches[@]}" -gt 1 ]; then
      echo "Multiple matching JARs found in $DIST_DIR; using the first one:" >&2
      for f in "${matches[@]}"; do printf '  %s\n' "$f"; done
    fi

    PROVIDER_JAR_PATH="${matches[0]}"
    PROVIDER_JAR_NAME="$(basename "$PROVIDER_JAR_PATH")"

  echo "Building docker image 'keycloak-cloudfront-auth-demo' with tags: ${tags[*]}"
  echo "  KC_VERSION=$KC_VERSION"
  echo "  PROVIDER_JAR_NAME=$PROVIDER_JAR_NAME"
  if [ "${#DOCKER_EXTRA_ARGS[@]}" -gt 0 ]; then
    echo "  docker build extra args: ${DOCKER_EXTRA_ARGS[*]}"
  fi

  # Ensure keycloak-config-cli jar is available in lib/ (download if needed)
  echo "Fetching keycloak-config-cli for Keycloak $KC_VERSION into lib/... if missing"
  scripts/fetch-kc-config-cli.sh "$KC_VERSION"

    build_tag_args=()
    for t in "${tags[@]}"; do
      if [ -z "$t" ]; then
        t=latest
      fi
      build_tag_args+=( -t "keycloak-cloudfront-auth-demo:${t}" )
    done

    docker_args=("${build_tag_args[@]}")
    if [ "${#PROGRESS_ARG[@]}" -gt 0 ]; then
      docker_args+=("${PROGRESS_ARG[@]}")
    fi
    if [ "${#DOCKER_EXTRA_ARGS[@]}" -gt 0 ]; then
      docker_args+=("${DOCKER_EXTRA_ARGS[@]}")
    fi
    docker build "${docker_args[@]}" -f docker/demo/Dockerfile \
      --build-arg KC_VERSION="$KC_VERSION" \
      --build-arg PROVIDER_JAR_NAME="$PROVIDER_JAR_NAME" \
      .
    ;;
  
  *)
    echo "Unknown subcommand: $1" >&2
    usage
    ;;
esac