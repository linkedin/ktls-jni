SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

PROJ_DIR=$(dirname "$SCRIPT_DIR")

SRC_PATH_CONTAINER=/tmp/ktls-jni

echo "Running the native build inside docker ..."
docker run  --user $(id -u):$(id -g) -v $PROJ_DIR:$SRC_PATH_CONTAINER ktls-jni-build ${SRC_PATH_CONTAINER}/scripts/build-native.sh
