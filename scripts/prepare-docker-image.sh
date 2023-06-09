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


docker build -t ktls-jni-build -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
