# Shared checks for the lab traffic scripts. Source it; do not run it.

# Stops with a clear message unless Docker is usable and every named
# container is running. Without this, a failed "docker exec" would look like
# a blocked connection or a failed login.
require_running() {
    if ! docker info >/dev/null 2>&1; then
        echo "Cannot use Docker as ${USER:-$(id -un)} (permission denied or Docker stopped)." >&2
        echo "Run 'sudo usermod -aG docker \$USER', then log out of Ubuntu and back in." >&2
        exit 1
    fi
    local container
    for container in "$@"; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != "true" ]; then
            echo "Container $container is not running." >&2
            echo "Start the lab: sudo containerlab deploy -t lab/logwatch.clab.yml" >&2
            exit 1
        fi
    done
}
