#!/bin/bash

# run.sh - Utility runner for this repository
# Subcommands:
#   build    -> wraps scripts/build.sh, accepts same args + -t/--test to run integration tests
#              When -t/--test is used, the script will run scripts/test-integration.sh after a successful build.
#              Pass --keep-containers to control test cleanup policy (forwarded to test-integration.sh).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$REPO_ROOT/scripts"

print_help() {
    cat <<'EOF'
Usage: $0 <command> [options] [args]

Commands:
    build           Build the project (wraps scripts/build.sh). See "$0 build --help" for details.
    docker-build    Build Docker images using scripts/docker-build.sh. See "$0 docker-build --help" for details.
    docker-run      Run predefined docker compose stacks (demo, dev-tests). See "$0 docker-run --help" for details.

Global help flags:
  -h, --help, help    Show this help
EOF
}

print_build_help() {
    cat <<'EOF'
Usage: $0 build [OPTIONS] [KEYCLOAK_VERSION] [BUILD_SUFFIX]

This runs scripts/build.sh with the same arguments. KEYCLOAK_VERSION accepts a version like
`26` or `26.0` or the literal `all` (default) to build/test all supported versions. Additional
options handled by this wrapper:
    -t, --test                  Run integration tests (scripts/test-integration.sh) if the build succeeds.
    --keep-containers=POLICY    Forwarded to tests when --test is used.
                                POLICY is one of: never (default), on-failure, always
    -r, --run                   After a successful build, run the `dev-tests` docker stack
                                for the built Keycloak version (uses scripts/docker-run.sh).
                                Incompatible with -t/--test.
    -h, --help, help            Show this help

Behavior on failure when using on-failure / always:
    If you pass --keep-containers=on-failure or --keep-containers=always
    and the tests fail, the test runner will stop running further Keycloak versions so
    you can inspect the running containers. Containers will NOT be removed by the
    test script in that case; run 'cd docker/dev-tests && docker-compose down -v --remove-orphans'
    manually when you are done inspecting.

Any other positional arguments are forwarded to scripts/build.sh unchanged.

Examples:
  $0 build                     # Run build for default (all)
  $0 build 26.0                # Build Keycloak 26.0
  $0 build 26.0 SNAPSHOT       # Build Keycloak 26.0 with SNAPSHOT suffix
    $0 build -t --keep-containers=always 26.0
    $0 build -r 26.3        # build and run the dev-tests stack for the built version
EOF
}

if [ $# -lt 1 ]; then
    print_help
    exit 1
fi

COMMAND="$1"
shift

# Ensure BUILD_ARGS is always defined (avoid "unbound variable" with set -u)
BUILD_ARGS=()

case "$COMMAND" in
    -h|--help|help)
        print_help
        exit 0
        ;;

    build)
    # Parse wrapper options for build
    TEST=false
    RUN=false
        KEEP_CONTAINERS=""
        BUILD_ARGS=()

        while [ $# -gt 0 ]; do
            case "$1" in
                -t|--test)
                    TEST=true
                    shift
                    ;;
                -r|--run)
                    RUN=true
                    shift
                    ;;
                --keep-containers=*)
                    KEEP_CONTAINERS="${1#*=}"
                    shift
                    ;;
                --keep-containers)
                    if [ $# -ge 2 ]; then
                        KEEP_CONTAINERS="$2"
                        shift 2
                    else
                        echo "[ERROR] --keep-containers requires a policy value"
                        exit 1
                    fi
                    ;;
                -h|--help|help)
                    print_build_help
                    exit 0
                    ;;
                --)
                    shift
                    while [ $# -gt 0 ]; do
                        BUILD_ARGS+=("$1")
                        shift
                    done
                    ;;
                *)
                    # Forward everything else to build.sh
                    BUILD_ARGS+=("$1")
                    shift
                    ;;
            esac
        done

        # Call the actual build script
        if [ "${#BUILD_ARGS[@]}" -gt 0 ]; then
            echo "Running build: $SCRIPTS_DIR/build.sh ${BUILD_ARGS[*]}"
        else
            echo "Running build: $SCRIPTS_DIR/build.sh"
        fi
        set +e
        "$SCRIPTS_DIR/build.sh" ${BUILD_ARGS[@]:-}
        build_rc=$?
        set -e

        if [ $build_rc -ne 0 ]; then
            echo "[ERROR] Build failed (exit code $build_rc)."
            exit $build_rc
        fi

        # Disallow running tests and auto-run simultaneously
        if [ "$RUN" = true ] && [ "$TEST" = true ]; then
            echo "[ERROR] -r/--run is incompatible with -t/--test" >&2
            exit 1
        fi

        # If requested, run integration tests
        if [ "$TEST" = true ]; then
            echo "Build succeeded. Running integration tests..."

            TEST_CMD=("$SCRIPTS_DIR/test-integration.sh")
            if [ -n "$KEEP_CONTAINERS" ]; then
                TEST_CMD+=("--keep-containers=$KEEP_CONTAINERS")
            fi

            # Extract version-like positional args from BUILD_ARGS to forward to tests.
            # Accept patterns like 26 or 26.0 and the literal "all".
            VERSIONS_TO_PASS=()
            for a in ${BUILD_ARGS[@]:-}; do
                if [[ "$a" =~ ^([0-9]+)(\.[0-9]+)?$ ]] || [ "$a" = "all" ]; then
                    VERSIONS_TO_PASS+=("$a")
                fi
            done

            if [ ${#VERSIONS_TO_PASS[@]} -gt 0 ]; then
                TEST_CMD+=("${VERSIONS_TO_PASS[@]}")
            fi

            echo "Running tests: ${TEST_CMD[*]}"
            set +e
            "${TEST_CMD[@]}"
            test_rc=$?
            set -e

            if [ $test_rc -ne 0 ]; then
                echo "[ERROR] Integration tests failed (exit code $test_rc)."
                exit $test_rc
            fi
        fi

        # If requested, run docker dev-tests for the newly built version(s)
        if [ "$RUN" = true ]; then
            # First prefer the version specified on the build command line (BUILD_ARGS)
            kc_version=""
            for a in ${BUILD_ARGS[@]:-}; do
                if [[ "$a" =~ ^([0-9]+)(\.[0-9]+)?$ ]] && [ -z "$kc_version" ]; then
                    kc_version="$a"
                fi
            done

            echo "--------------------------------------------------"
            echo "# -r / --run option provided"
            echo "# Run './scripts/docker-run.sh dev-tests -d'"
            echo "--------------------------------------------------"

            if [ -n "$kc_version" ]; then
                echo "Using Keycloak version from build args: $kc_version"
                PARENT_CMD="$0 docker-run" "$SCRIPTS_DIR/docker-run.sh" dev-tests -d "$kc_version"
                rc=$?
                if [ $rc -ne 0 ]; then
                    echo "[ERROR] docker-run failed (exit code $rc)."
                    exit $rc
                fi
            else
                # Fall back to detecting the latest JAR in dist/
                if [ -d "$REPO_ROOT/dist" ]; then
                    latest_jar=$(ls -t "$REPO_ROOT/dist"/keycloak-cloudfront-auth-*-KC*.jar 2>/dev/null | head -1 || true)
                    if [ -n "$latest_jar" ]; then
                        # Use POSIX-compatible sed to extract version like 26.3
                        kc_version=$(basename "$latest_jar" | sed -n 's/.*-KC\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
                        if [ -n "$kc_version" ]; then
                            echo "Use latest Keycloak version: $kc_version"
                            PARENT_CMD="$0 docker-run" "$SCRIPTS_DIR/docker-run.sh" dev-tests -d "$kc_version"
                            rc=$?
                            if [ $rc -ne 0 ]; then
                                echo "[ERROR] docker-run failed (exit code $rc)."
                                exit $rc
                            fi
                        else
                            echo "[ERROR] Could not determine built Keycloak version from: $latest_jar" >&2
                            exit 1
                        fi
                    else
                        echo "[ERROR] No built JARs found in dist/ to determine KC version." >&2
                        exit 1
                    fi
                else
                    echo "[ERROR] dist/ directory not found; cannot auto-run dev-tests." >&2
                    exit 1
                fi
            fi
        fi

        echo "Build (and optional tests) completed successfully."
        ;;
    
    docker-build)
        # Delegate to scripts/docker-build.sh
        if [ "$#" -eq 0 ]; then
            PARENT_CMD="$0 docker-build" "$SCRIPTS_DIR/docker-build.sh" help
        fi

        PARENT_CMD="$0 docker-build" "$SCRIPTS_DIR/docker-build.sh" "$@"
        rc=$?
        if [ $rc -ne 0 ]; then
            echo "[ERROR] docker-build failed (exit code $rc)."
            exit $rc
        fi
        ;;

    docker-run)
        # Delegate to scripts/docker-run.sh
        if [ "$#" -eq 0 ]; then
            PARENT_CMD="$0 docker-run" "$SCRIPTS_DIR/docker-run.sh" help
        fi

        PARENT_CMD="$0 docker-run" "$SCRIPTS_DIR/docker-run.sh" "$@"
        rc=$?
        if [ $rc -ne 0 ]; then
            echo "[ERROR] docker-run failed (exit code $rc)."
            exit $rc
        fi
        ;;
    
    *)
        echo "[ERROR] Unknown command: $COMMAND"
        print_help
        exit 1
        ;;
esac

exit 0
