#!/bin/sh
set -eu
cd "$(dirname "$0")"

SDK=${ANDROID_HOME:-/opt/android-sdk}
BUILD_TOOLS=$(ls -d "$SDK"/build-tools/* | sort -V | tail -n 1)
PLATFORM=$(ls -d "$SDK"/platforms/android-* | sort -V | tail -n 1)
ANDROID_JAR=$PLATFORM/android.jar
MIN_SDK=31
TARGET_SDK=35
KEYSTORE=${TAPUNLOCK_KEYSTORE:-$HOME/.android/tap-unlock.jks}
KEYSTORE_PASS_FILE=$KEYSTORE.pass

rm -rf build
mkdir -p build/classes build/dex

javac -source 17 -target 17 -encoding UTF-8 -Xlint:-options -Xlint:deprecation \
    -classpath "$ANDROID_JAR" -d build/classes $(find src -name '*.java')
"$BUILD_TOOLS"/d8 --release --min-api "$MIN_SDK" --lib "$ANDROID_JAR" \
    --output build/dex $(find build/classes -name '*.class')
"$BUILD_TOOLS"/aapt2 link -o build/unsigned.apk -I "$ANDROID_JAR" --manifest AndroidManifest.xml \
    --min-sdk-version "$MIN_SDK" --target-sdk-version "$TARGET_SDK"
python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1], "a").write(sys.argv[2], "classes.dex")' \
    build/unsigned.apk build/dex/classes.dex
"$BUILD_TOOLS"/zipalign -f -p 4 build/unsigned.apk build/aligned.apk

if [ ! -f "$KEYSTORE" ]; then
    mkdir -p "$(dirname "$KEYSTORE")"
    (umask 077; head -c 24 /dev/urandom | base64 > "$KEYSTORE_PASS_FILE")
    keytool -genkeypair -keystore "$KEYSTORE" -storepass:file "$KEYSTORE_PASS_FILE" \
        -alias tap-unlock -keyalg EC -groupname secp256r1 -validity 10000 \
        -dname "CN=Tap Unlock" >/dev/null
fi
"$BUILD_TOOLS"/apksigner sign --ks "$KEYSTORE" --ks-pass "file:$KEYSTORE_PASS_FILE" \
    --out build/tap-unlock.apk build/aligned.apk
"$BUILD_TOOLS"/apksigner verify build/tap-unlock.apk
echo "built $(pwd)/build/tap-unlock.apk"
