#!/bin/bash

# Available Keycloak versions supported by this extension
KEYCLOAK_VERSIONS=("23.0" "24.0" "25.0" "26.0")

show_help() {
    echo -e "Keycloak CloudFront Auth Integration Tests\n"
    echo -e "Usage: $0 [OPTIONS] [KEYCLOAK_VERSION]\n"
    echo "Arguments:"
    echo "  - KEYCLOAK_VERSION:     Keycloak version to test (${KEYCLOAK_VERSIONS[*]} or all). Default: all"
    echo -e "\nOptions:"
    echo "  --keep-containers=POLICY    Container cleanup policy:"
    echo "                             - always-remove (default): Always remove containers after tests"
    echo "                             - keep-on-failure: Keep containers only if tests fail"
    echo "                             - always-keep: Never remove containers"
    echo "  -h, --help, help           Show this help"
    echo -e "\nExamples:"
    echo "  $0                              # Test all versions, remove containers"
    echo "  $0 26.0                         # Test only Keycloak 26.0, remove containers"
    echo "  $0 23.0 24.0                    # Test Keycloak 23.0 and 24.0, remove containers"
    echo "  $0 --keep-containers=always-keep 26.0  # Test Keycloak 26.0, keep containers"
    echo "  $0 --keep-containers=keep-on-failure 26.0  # Keep containers if tests fail"
    echo -e "\nSupported Keycloak versions: ${KEYCLOAK_VERSIONS[*]}\n"
}

# Check if help is requested
if [[ "$1" == "-h" || "$1" == "--help" || "$1" == "help" ]]; then
    show_help
    exit 0
fi

# Default container cleanup policy
CONTAINER_CLEANUP_POLICY="always-remove"

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
                echo "[ERROR] --keep-containers requires a policy (always-remove, keep-on-failure, always-keep)"
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
    always-remove|keep-on-failure|always-keep)
        ;;
    *)
        echo "[ERROR] Invalid container cleanup policy: $CONTAINER_CLEANUP_POLICY"
        echo "Valid values: always-remove, keep-on-failure, always-keep"
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
    kc_major_version="${kc_version%%.*}"
    kc_minor_version="${kc_version#*.}"
    # Step 1: Clean up existing Docker containers
    echo "Cleaning up existing Docker containers..."
    cd testing/docker
    docker-compose down -v --remove-orphans > /dev/null 2>&1
    cd ../..
    
    # Step 2: Copy selected JAR from dist/ to providers directory
    echo "Preparing extension JAR for Keycloak $kc_version..."
    PROVIDERS_DIR="testing/docker/mounts/configurator/providers"
    rm -rf "$PROVIDERS_DIR"/*

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

    echo "Using JAR: $JAR_FILE"
    echo "Copying JAR: $JAR_FILE to $PROVIDERS_DIR"
    cp "$JAR_FILE" "$PROVIDERS_DIR/"
    
    # Step 3: Launch Docker Compose
    echo "Starting Keycloak with Docker Compose..."
    cd testing/docker
    # Export version vars for Docker and tests
    export KEYCLOAK_VERSION="$kc_version"
    export KEYCLOAK_VERSION_MAJOR="$kc_major_version"
    export KEYCLOAK_VERSION_MINOR="$kc_minor_version"
    docker-compose up -d
    
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to start Docker Compose"
        cd ../..
        FAILED_TESTS+=("Keycloak $kc_version - Docker startup failed")
        continue
    fi
    
    # Step 4: Wait for configurator to finish (improved: detect failure + show logs)
    echo "Waiting for configurator to complete..."
    max_wait=300  # 5 minutes max
    wait_time=0
    configurator_failed=false
    configurator_reason=""

    while [ $wait_time -lt $max_wait ]; do
        # Get configurator container id (prefer docker-compose, fallback to docker by label)
        container_id=$(docker-compose ps -q configurator 2>/dev/null)
        if [ -z "$container_id" ]; then
            # Try to find any container created by this compose for service 'configurator'
            container_id=$(docker ps -a --filter "label=com.docker.compose.service=configurator" --format "{{.ID}}" | head -n1 2>/dev/null || true)
        fi

        if [ -z "$container_id" ]; then
            configurator_failed=true
            configurator_reason="configurator container not found"
            echo "[ERROR] Configurator container not found."
            break
        fi

        # Check if configurator is still running
        running=$(docker inspect --format='{{.State.Running}}' "$container_id" 2>/dev/null || echo "false")
        if [ "$running" = "true" ]; then
            echo "Configurator still running... (${wait_time}s elapsed)"
            sleep 10
            wait_time=$((wait_time + 10))
            continue
        fi

        # Container finished — inspect exit code
        exit_code=$(docker inspect --format='{{.State.ExitCode}}' "$container_id" 2>/dev/null || echo "1")
        if [ "$exit_code" -ne 0 ]; then
            configurator_failed=true
            configurator_reason="configurator exited with code $exit_code"
            echo "[ERROR] Configurator failed with exit code $exit_code"
            echo "---- Last configurator logs (tail 200) ----"
            docker logs --tail 200 "$container_id" || true
            echo "-------------------------------------------"
        else
            echo "Configurator finished successfully."
        fi

        break
    done

    if [ $wait_time -ge $max_wait ]; then
        configurator_failed=true
        configurator_reason="configurator timeout after ${max_wait}s"
        echo "[ERROR] Configurator did not finish within timeout (${max_wait}s)"
        container_id=$(docker-compose ps -q configurator 2>/dev/null)
        if [ -n "$container_id" ]; then
            echo "---- Last configurator logs (tail 200) ----"
            docker logs --tail 200 "$container_id" || true
            echo "-------------------------------------------"
        fi
    fi

        if [ "$configurator_failed" = true ]; then
            # Honor container cleanup policy: if user asked to keep containers on failure, don't remove them
            if [ "$CONTAINER_CLEANUP_POLICY" = "always-remove" ]; then
                echo "Cleaning up Docker containers (policy: always-remove)..."
                docker-compose down -v --remove-orphans > /dev/null 2>&1
                cd ../..
            else
                echo "Keeping Docker containers for debugging (policy: $CONTAINER_CLEANUP_POLICY)"
                echo "To manually clean up later: cd testing/docker && docker-compose down -v --remove-orphans"
                cd ../..
            fi

            FAILED_TESTS+=("Keycloak $kc_version - configurator failed: $configurator_reason")
            continue
        fi
    
    # Step 5: Wait a bit more for Keycloak to be fully ready
    echo "Waiting for Keycloak to be fully ready..."
    sleep 10
    
    # Step 6: Run Java integration tests against the running Docker setup
    cd ../..  # Back to project root
    echo "Running Java integration tests against Docker Keycloak..."
    
    # Set environment variables for the test
    export KEYCLOAK_HOST=localhost
    export KEYCLOAK_PORT=8080
    
    # Run the tests and pass keycloak-version.major/minor to Maven so POM resolves correctly
    mvn failsafe:integration-test failsafe:verify -Dkeycloak-version.major="$kc_major_version" -Dkeycloak-version.minor="$kc_minor_version" -Dmaven.test.skip=false -DskipUTs=true
    
    test_result=$?
    
    # Step 7: Clean up Docker containers based on policy
    should_cleanup=false
    case "$CONTAINER_CLEANUP_POLICY" in
        always-remove)
            should_cleanup=true
            echo "Cleaning up Docker containers (policy: always-remove)..."
            ;;
        keep-on-failure)
            if [ $test_result -eq 0 ]; then
                should_cleanup=true
                echo "Cleaning up Docker containers (policy: keep-on-failure, tests passed)..."
            else
                echo "Keeping Docker containers for debugging (policy: keep-on-failure, tests failed)..."
                echo "To manually clean up later: cd testing/docker && docker-compose down -v --remove-orphans"
            fi
            ;;
        always-keep)
            echo "Keeping Docker containers (policy: always-keep)..."
            echo "To manually clean up: cd testing/docker && docker-compose down -v --remove-orphans"
            ;;
    esac
    
    if [ "$should_cleanup" = true ]; then
        cd testing/docker
        docker-compose down -v --remove-orphans > /dev/null 2>&1
        cd ../..
    fi
    
    if [ $test_result -eq 0 ]; then
        echo "[SUCCESS] Tests passed for Keycloak $kc_version"
        SUCCESSFUL_TESTS+=("Keycloak $kc_version")
    else
        echo "[ERROR] Tests failed for Keycloak $kc_version"
        FAILED_TESTS+=("Keycloak $kc_version - tests failed")
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
