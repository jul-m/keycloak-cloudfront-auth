#!/bin/bash

# Configure mvn options: add --no-transfer-progress when running inside GitHub Actions
if [ "${GITHUB_ACTIONS:-false}" = "true" ]; then
    mvn_opts="--no-transfer-progress"
else
    mvn_opts=""
fi

docker_down_stack() {
    # $1 = stack name
    ./scripts/docker-run.sh "$1" down ${@:2}
}

# Available Keycloak versions supported by this extension
KEYCLOAK_VERSIONS=("23.0" "24.0" "25.0" "26.0")

show_help() {
    echo -e "Keycloak CloudFront Auth Integration Tests\n"
    echo -e "Usage: $0 [OPTIONS] [KEYCLOAK_VERSION]\n"
    echo "Arguments:"
    echo "  - KEYCLOAK_VERSION:     Keycloak version to test (${KEYCLOAK_VERSIONS[*]} or all). Default: all"
    echo -e "\nOptions:"
    echo "  --keep-containers=POLICY    Container cleanup policy:"
    echo "                             - never (default): Always remove containers after tests"
    echo "                             - on-failure: Keep containers only if tests fail"
    echo "                             - always: Never remove containers"
    echo "\nBehavior on failure when using on-failure / always:" 
    echo "  If you pass --keep-containers=on-failure or --keep-containers=always,"
    echo "  the script will stop running further versions when a failure occurs so you can"
    echo "  inspect the running containers. Containers will NOT be removed by this script"
    echo "  in that case; run './scripts/docker-run.sh down dev-tests'"
    echo "  manually when finished."
    echo "  -h, --help, help           Show this help"
    echo -e "\nExamples:"
    echo "  $0                              # Test all versions, remove containers"
    echo "  $0 26.0                         # Test only Keycloak 26.0, remove containers"
    echo "  $0 23.0 24.0                    # Test Keycloak 23.0 and 24.0, remove containers"
    echo "  $0 --keep-containers=always 26.0  # Test Keycloak 26.0, keep containers"
    echo "  $0 --keep-containers=on-failure 26.0  # Keep containers if tests fail"
    echo -e "\nSupported Keycloak versions: ${KEYCLOAK_VERSIONS[*]}\n"
}

# Check if help is requested
if [[ "$1" == "-h" || "$1" == "--help" || "$1" == "help" ]]; then
    show_help
    exit 0
fi

# Default container cleanup policy
CONTAINER_CLEANUP_POLICY="never"

# Parse arguments
VERSIONS_TO_TEST=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-containers=*)
            CONTAINER_CLEANUP_POLICY="${1#*=}"
            shift
            ;;
        --keep-containers)
            if [[ -n $2 && $2 != --* ]]; then
                CONTAINER_CLEANUP_POLICY="$2"
                shift 2
            else
                echo "[ERROR] --keep-containers requires a policy (never, on-failure, always)"
                exit 1
            fi
            ;;
        -h|--help|help)
            show_help
            exit 0
            ;;
        -*)
            echo "[ERROR] Unknown option: $1"
            exit 1
            ;;
        *)
            # This is a version number
            VERSIONS_TO_TEST+=("$1")
            shift
            ;;
    esac
done

# Validate container cleanup policy
case "$CONTAINER_CLEANUP_POLICY" in
    never|on-failure|always)
        ;;
    *)
        echo "[ERROR] Invalid container cleanup policy: $CONTAINER_CLEANUP_POLICY"
        echo "Valid values: never, on-failure, always"
        exit 1
        ;;
esac

# Discover available JARs in dist/ and map them to Keycloak versions.
# macOS ships bash 3.x which doesn't support associative arrays, so use
# two parallel arrays: VERSIONS_AVAILABLE and JARS_AVAILABLE.
DIST_DIR="dist"
if [ ! -d "$DIST_DIR" ]; then
    echo "[ERROR] dist/ directory not found. Place built JARs into $DIST_DIR/ before running this script."
    exit 1
fi

VERSIONS_AVAILABLE=()
JARS_AVAILABLE=()

shopt -s nullglob
for j in "$DIST_DIR"/*.jar; do
    base=$(basename "$j")
    # extract version after KC or kc (e.g. KC26.0 or kc26) using BSD sed (-E)
    ver=$(echo "$base" | sed -E -n 's/.*[Kk][Cc]([0-9]+(\.[0-9]+)?).*/\1/p')
    if [ -n "$ver" ]; then
        # check if version already seen
        found_index=-1
        for i in "${!VERSIONS_AVAILABLE[@]}"; do
            if [ "${VERSIONS_AVAILABLE[$i]}" = "$ver" ]; then
                found_index=$i
                break
            fi
        done

        if [ $found_index -ge 0 ]; then
            # keep the most recent JAR for this version
            if [ "$j" -nt "${JARS_AVAILABLE[$found_index]}" ]; then
                JARS_AVAILABLE[$found_index]="$j"
            fi
        else
            VERSIONS_AVAILABLE+=("$ver")
            JARS_AVAILABLE+=("$j")
        fi
    fi
done
shopt -u nullglob

if [ ${#VERSIONS_AVAILABLE[@]} -eq 0 ]; then
    echo "[ERROR] No JARs with a Keycloak 'KC' version marker found in $DIST_DIR/."
    echo "Place JARs named like '*KC26.0*.jar' in $DIST_DIR/ and re-run."
    exit 1
fi

# If user did not pass versions on the command line, test all discovered versions.
if [ ${#VERSIONS_TO_TEST[@]} -eq 0 ]; then
    VERSIONS_TO_TEST=()
    for k in "${VERSIONS_AVAILABLE[@]}"; do
        VERSIONS_TO_TEST+=("$k")
    done
    # sort versions for deterministic order (numeric sort works for major.minor patterns)
    IFS=$'\n' VERSIONS_TO_TEST=($(printf "%s\n" "${VERSIONS_TO_TEST[@]}" | sort -n))
    unset IFS
else
    # If user explicitly passed "all", run for all discovered versions.
    for v in "${VERSIONS_TO_TEST[@]}"; do
        if [ "$v" = "all" ]; then
            VERSIONS_TO_TEST=()
            for k in "${VERSIONS_AVAILABLE[@]}"; do
                VERSIONS_TO_TEST+=("$k")
            done
            IFS=$'\n' VERSIONS_TO_TEST=($(printf "%s\n" "${VERSIONS_TO_TEST[@]}" | sort -n))
            unset IFS
            break
        fi
    done

    # Validate specified versions exist among discovered JARs
    VALIDATED_VERSIONS=()
    for version in "${VERSIONS_TO_TEST[@]}"; do
        present=false
        for v in "${VERSIONS_AVAILABLE[@]}"; do
            if [ "$v" = "$version" ]; then
                present=true
                break
            fi
        done
        if [ "$present" = true ]; then
            VALIDATED_VERSIONS+=("$version")
        else
            echo "[ERROR] No JAR found for requested Keycloak version: $version"
            echo -n "Available versions from $DIST_DIR/:"
            for v in "${VERSIONS_AVAILABLE[@]}"; do echo -n " $v"; done
            echo
            exit 1
        fi
    done
    VERSIONS_TO_TEST=("${VALIDATED_VERSIONS[@]}")
fi

echo "Container cleanup policy: $CONTAINER_CLEANUP_POLICY"
echo "Testing versions: ${VERSIONS_TO_TEST[*]}"

# Results tracking
SUCCESSFUL_TESTS=()
FAILED_TESTS=()

# Ensure Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "[ERROR] Docker is not running. Please start Docker and try again."
    exit 1
fi

for kc_version in "${VERSIONS_TO_TEST[@]}"; do
    echo "========================================================="
    echo "Testing with Keycloak $kc_version"
    echo "========================================================="
    # Split version format VV.N into major and minor (e.g., 26.3 -> major=26 minor=3)
    # Step 1: Clean up existing Docker containers
    echo "Cleaning up existing Docker containers..."
    # Use centralized helper to manage docker compose projects
    docker_down_stack dev-tests > /dev/null 2>&1 || true

    # find corresponding JAR from VERSIONS_AVAILABLE/JARS_AVAILABLE
    JAR_FILE=""
    for i in "${!VERSIONS_AVAILABLE[@]}"; do
        if [ "${VERSIONS_AVAILABLE[$i]}" = "$kc_version" ]; then
            JAR_FILE="${JARS_AVAILABLE[$i]}"
            break
        fi
    done
    if [ -z "$JAR_FILE" ]; then
        echo "[ERROR] No JAR found for Keycloak $kc_version"
        FAILED_TESTS+=("Keycloak $kc_version - JAR not found")
        continue
    fi

    echo "Found provider JAR: $JAR_FILE"

    # Step 3: Launch via centralized script and pass Keycloak version to docker-run
    echo "Starting Keycloak with Docker (via ./scripts/docker-run.sh)..."
    ./scripts/docker-run.sh dev-tests up "$kc_version" -d --vars KCA_PROVIDER_JAR_NAME="$(basename $JAR_FILE)"

    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to start Docker via docker-run.sh"
        FAILED_TESTS+=("Keycloak $kc_version - Docker startup failed")
        continue
    fi
    
    # Step 4: Wait for Keycloak configuration import to finish
    echo "Waiting for Keycloak configuration import to complete..."
    max_wait=300  # 5 minutes max
    wait_time=0
    configurator_failed=false
    configurator_reason=""

    # The ini script runs inside the keycloak container; locate that container by name
    kc_container=""
    while [ $wait_time -lt $max_wait ]; do
        kc_container=$(docker ps -a --filter "name=kc-cloudfront-auth_keycloak" --format "{{.ID}}" | head -n1 2>/dev/null || true)

        if [ -z "$kc_container" ]; then
            configurator_failed=true
            configurator_reason="keycloak container not found"
            echo "[ERROR] Keycloak container not found."
            break
        fi

        # Check logs for success marker
        if docker logs --tail 200 "$kc_container" 2>/dev/null | grep -q "Keycloak configuration imported successfully\."; then
            echo "Keycloak configuration import finished successfully."
            break
        fi

        # Check if keycloak container exited unexpectedly
        running=$(docker inspect --format='{{.State.Running}}' "$kc_container" 2>/dev/null || echo "false")
        if [ "$running" != "true" ]; then
            exit_code=$(docker inspect --format='{{.State.ExitCode}}' "$kc_container" 2>/dev/null || echo "1")
            configurator_failed=true
            configurator_reason="keycloak container exited with code $exit_code"
            echo "[ERROR] Keycloak container exited with code $exit_code"
            echo "---- Last keycloak logs (tail 200) ----"
            docker logs --tail 200 "$kc_container" || true
            echo "-------------------------------------------"
            break
        fi

        echo "Waiting for Keycloak configuration import... (${wait_time}s elapsed)"
        sleep 5
        wait_time=$((wait_time + 5))
    done

    if [ $wait_time -ge $max_wait ]; then
        configurator_failed=true
        configurator_reason="configuration import timeout after ${max_wait}s"
        echo "[ERROR] Configuration import did not finish within timeout (${max_wait}s)"
        if [ -n "$kc_container" ]; then
            echo "---- Last keycloak logs (tail 200) ----"
            docker logs --tail 200 "$kc_container" || true
            echo "-------------------------------------------"
        fi
    fi

        if [ "$configurator_failed" = true ]; then
            # Honor container cleanup policy: if user asked to keep containers on failure, don't remove them
            if [ "$CONTAINER_CLEANUP_POLICY" = "never" ]; then
                echo "Cleaning up Docker containers (policy: never)..."
                docker_down_stack dev-tests > /dev/null 2>&1 || true
                FAILED_TESTS+=("Keycloak $kc_version - configurator failed: $configurator_reason")
                # continue to next version
                continue
            else
                echo "Keeping Docker containers for debugging (policy: $CONTAINER_CLEANUP_POLICY)"
                echo "To manually clean up later: ./scripts/docker-run.sh down dev-tests"
                FAILED_TESTS+=("Keycloak $kc_version - configurator failed: $configurator_reason")
                echo "Stopping further tests so you can inspect containers (policy: $CONTAINER_CLEANUP_POLICY)."
                break
            fi
        fi
    
    # Step 5: Wait a bit more for Keycloak to be fully ready
    echo "Waiting for Keycloak to be fully ready..."
    sleep 5
    
    # Step 6: Run Java integration tests against the running Docker setup
    echo "Running Java integration tests against Docker Keycloak..."
    
    # Compute build-name from the JAR file name so tests can verify the Version operational info
    jar_basename=$(basename "$JAR_FILE")
    # Expect jar name like keycloak-cloudfront-auth-<build-name>.jar
    BUILD_NAME=$(echo "$jar_basename" | sed -E 's/^keycloak-cloudfront-auth-(.*)\.jar$/\1/')

    # Run the tests and pass keycloak-version.major-minor to Maven so POM resolves correctly
    mvn $mvn_opts failsafe:integration-test failsafe:verify -Dmaven.test.skip=false -DskipUTs=true \
        -Dkeycloak-version.major-minor="$kc_version" -Dbuild-name="$BUILD_NAME"

    test_result=$?
    
    # Step 7: Clean up Docker containers based on policy
    should_cleanup=false
    case "$CONTAINER_CLEANUP_POLICY" in
        never)
            should_cleanup=true
            echo "Cleaning up Docker containers (policy: never)..."
            ;;
        on-failure)
            if [ $test_result -eq 0 ]; then
                should_cleanup=true
                echo "Cleaning up Docker containers (policy: on-failure, tests passed)..."
            else
                echo "Keeping Docker containers for debugging (policy: on-failure, tests failed)..."
                echo "To manually clean up later: ./scripts/docker-run.sh down dev-tests"
            fi
            ;;
        always)
            echo "Keeping Docker containers (policy: always)..."
            echo "To manually clean up: ./scripts/docker-run.sh down dev-tests"
            ;;
    esac
    
    if [ "$should_cleanup" = true ]; then
    docker_down_stack dev-tests > /dev/null 2>&1 || true
    fi
    
    if [ $test_result -eq 0 ]; then
        echo "[SUCCESS] Tests passed for Keycloak $kc_version"
        SUCCESSFUL_TESTS+=("Keycloak $kc_version")
    else
        echo "[ERROR] Tests failed for Keycloak $kc_version"
        FAILED_TESTS+=("Keycloak $kc_version - tests failed")
        # If user asked to keep containers, stop running further versions so they can inspect
        if [ "$CONTAINER_CLEANUP_POLICY" = "on-failure" ] || [ "$CONTAINER_CLEANUP_POLICY" = "always" ]; then
            echo "Stopping further tests because containers are being kept for debugging (policy: $CONTAINER_CLEANUP_POLICY)."
            break
        fi
    fi
    
    echo ""
done

# Print summary
echo ""
echo "========================================================="
echo "Test Summary:"
echo "========================================================="
if [ ${#SUCCESSFUL_TESTS[@]} -gt 0 ]; then
    echo "✅ Successful tests:"
    for version in "${SUCCESSFUL_TESTS[@]}"; do
        echo "  - $version"
    done
fi

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo ""
    echo "❌ Failed tests:"
    for version in "${FAILED_TESTS[@]}"; do
        echo "  - $version"
    done
    exit 1
fi

if [ ${#SUCCESSFUL_TESTS[@]} -eq 0 ]; then
    echo "❌ No tests were executed successfully."
    exit 1
fi

echo ""
echo "🎉 All tests completed successfully!"
exit 0
