SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

PROJ_DIR=$(dirname "$SCRIPT_DIR")

SRC_PATH_CONTAINER=/tmp/ktls-jni

echo "Removing build folder ..."
rm -rf build

echo "Starting build-native.sh ..."
docker run -v ${PROJ_DIR}:${SRC_PATH_CONTAINER} --user $(id -u):$(id -g)  ktls-jni-build ${SRC_PATH_CONTAINER}/scripts/build-native.sh

