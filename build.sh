#!/bin/sh

# Simple shell script to copy resources and build jar files.
# Note that there's probably an easier way to do this, but i'm no Java or Gradle wizard ;)
# See https://github.com/sleeyax/burp-awesome-tls/issues/13 if you want to help out. Any help is appreciated!

buildJar() {
  local targetPlatform="$1"
  echo "building $targetPlatform jar"
  ./gradlew buildJar
  mv ./build/libs/burp-awesome-tls.jar "./build/libs/Burp-Awesome-TLS-$targetPlatform.jar"
}

cleanup() {
  rm --recursive --dir --verbose ./src/main/resources/*
}

copy() {
  # params
  local binary=$1
  local resourceFolder=$2
  local extension="${binary##*.}"

  # locations to copy to and from
  local binaryPath="./src-go/server/build/$binary"
  local resourcePath="./src/main/resources/$resourceFolder/server.$extension"

  # perform copy
  mkdir -p $(dirname "$resourcePath")
  cp $binaryPath $resourcePath
  echo "copied $binaryPath to $resourcePath"
}

copy_macos() {
  copy "server-darwin-10.16-amd64.dylib" "darwin-x86-64"
}

copy_linux_386() {
  copy "server-linux-386.so" "linux-x86"
}

copy_linux_amd64() {
  copy "server-linux-amd64.so" "linux-x86-64"
}

copy_windows_amd64() {
  copy "server-windows-4.0-amd64.dll" "win32-x86-64"
}

copy_windows_386() {
  copy "server-windows-4.0-386.dll" "win32-x86"
}

# build separate jar files per platform
cleanup
copy_macos
buildJar "macos-amd64"

cleanup
copy_linux_386
buildJar "linux-i386"

cleanup
copy_linux_amd64
buildJar "linux-amd64"

cleanup
copy_windows_amd64
buildJar "windows-amd64"

cleanup
copy_windows_386
buildJar "windows-i386"

# build single cross-platform fat jar
cleanup
copy_macos
copy_linux_386
copy_linux_amd64
copy_windows_amd64
copy_windows_386
buildJar "fat"
