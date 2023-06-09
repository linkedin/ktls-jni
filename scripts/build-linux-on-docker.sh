
SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

# Traverse upwards until the project directory is found
while [ ! -d "$SCRIPT_DIR/ktls-jni" ] && [ "$SCRIPT_DIR" != "/" ]; do
    SCRIPT_DIR=$(dirname "$SCRIPT_DIR")
done

# Check if the project directory is found
if [ -d "$SCRIPT_DIR/ktls-jni" ]; then
    SCRIPT_DIR=$SCRIPT_DIR/ktls-jni
else
    echo "Project directory not found."
fi

echo $SCRIPT_DIR
SRC_PATH_CONTAINER=/tmp/ktls-jni

echo "Removing build folder ..."
rm -rf build

echo "Starting build-native.sh ..."
docker run -it -v ${SCRIPT_DIR}:${SRC_PATH_CONTAINER} --user $(id -u):$(id -g)  ktls-jni-build ${SRC_PATH_CONTAINER}/scripts/build-native.sh





