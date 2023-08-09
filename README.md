# ktls-jni

A plugin for enabling kernel TLS on Java systems

## Author/Contributor

maintained by [LinkedIn](https://github.com/linkedin)

# About the project
This library provides a way for Java-based applications to take advantage of in-kernel TLS encryption and decryption available in modern Linux kernels.
The project is structured as a JNI library and the corresponding C++ class that makes appropriate system calls to enable in-kernel TLS on a socket.

# Build requirements
Building the dynamically linked library (`.so` file) that makes the necessary system calls requires Kernel TLS to be supported on the system that is being used for the build. It requires the presence of some kernel header files that would only be present on a host running a sufficiently recent Linux distribution (with Kernel version >= 4.17).

However, for ease of use and development, we wanted developers using older Linux hosts or MacOS to be able to build the library. To achieve this, we use docker to build the library on the base image with jdk and libstdc++ .

Pre-requisites for the build are `docker`.

# How to build
There are two options of building the project with respect to the os Version.
In order to build the project with docker by default, just run

`./gradlew build`

This invokes the native build script from within the docker container.

Else, a flag needs to specified to build using the native build script.

`./gradlew build -PbuildType=native`

This should build the JAR containing the Java classes as well as the `.so` file.
