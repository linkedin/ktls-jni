SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

PROJ_DIR=$(dirname "$SCRIPT_DIR")

docker build -t ktls-jni-build -f "$PROJ_DIR/Dockerfile" "$SCRIPT_DIR"
