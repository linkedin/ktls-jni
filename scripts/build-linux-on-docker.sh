REPO_ROOT_PATH=$(pwd)

SRC_PATH_CONTAINER=/tmp/ktls-jni

echo "Removing build folder ..."
rm -rf build

echo "Starting build-native.sh ..."
docker run -it -v ${REPO_ROOT_PATH}:${SRC_PATH_CONTAINER} --user $(id -u):$(id -g)  ktls-jni-build ${SRC_PATH_CONTAINER}/scripts/build-native.sh
