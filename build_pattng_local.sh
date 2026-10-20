#!/usr/bin/env bash
set -e

ROOT_DIR="/workspaces/PattNG"
cd "$ROOT_DIR"

echo "=== [1/6] Setting up Java & Android SDK/NDK Environment ==="
if [ -d "/usr/lib/jvm/java-21-openjdk-amd64" ]; then
    export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
elif [ -d "/usr/lib/jvm/java-17-openjdk-amd64" ]; then
    export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
else
    sudo apt-get update -y && sudo apt-get install -y openjdk-17-jdk
    export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
fi

export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
mkdir -p "$ANDROID_HOME/cmdline-tools"

if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
    echo "Downloading Android cmdline-tools..."
    curl -sSL "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" -o /tmp/cmdtools.zip
    unzip -q -o /tmp/cmdtools.zip -d "$ANDROID_HOME/cmdline-tools"
    mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
    rm -f /tmp/cmdtools.zip
fi

export GOPATH="$(go env GOPATH)"
export PATH="$JAVA_HOME/bin:$GOPATH/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

# Ensure NDK is installed
if [ ! -d "$ANDROID_HOME/ndk" ] || [ -z "$(ls -A "$ANDROID_HOME/ndk" 2>/dev/null)" ]; then
    echo "Installing Android SDK Platform & NDK..."
    yes | sdkmanager --licenses > /dev/null || true
    sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;27.1.12297006"
fi

LATEST_NDK="$(ls -1 "$ANDROID_HOME/ndk" | sort -V | tail -n 1)"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$LATEST_NDK"
export NDK_HOME="$ANDROID_NDK_HOME"
echo "Using JAVA_HOME=$JAVA_HOME"
echo "Using ANDROID_NDK_HOME=$ANDROID_NDK_HOME"

echo "=== [2/6] Extracting prebuilt Aether/HevTun/Psiphon native libs (Fast Track) ==="
mkdir -p "$ROOT_DIR/V2rayNG/app/libs/arm64-v8a"
mkdir -p "$ROOT_DIR/V2rayNG/app/libs/armeabi-v7a"
mkdir -p "$ROOT_DIR/V2rayNG/app/libs/x86_64"

if [ ! -f "$ROOT_DIR/V2rayNG/app/libs/armeabi-v7a/libhevtun.so" ]; then
    echo "Fetching latest release universal APK from patterniha/PattNG to extract unmodified C/Rust .so files..."
    LATEST_APK_URL=$(curl -sSL https://api.github.com/repos/patterniha/PattNG/releases/latest \
        | grep -o '"browser_download_url": *"[^"]*universal[^"]*\.apk"' \
        | head -n 1 | cut -d '"' -f 4)

    if [ -n "$LATEST_APK_URL" ]; then
        curl -sSL "$LATEST_APK_URL" -o /tmp/pattng_ref.apk
        rm -rf /tmp/pattng_ref_unzip
        mkdir -p /tmp/pattng_ref_unzip
        unzip -q -o /tmp/pattng_ref.apk "lib/*" -d /tmp/pattng_ref_unzip
        for abi in arm64-v8a armeabi-v7a x86_64; do
            if [ -d "/tmp/pattng_ref_unzip/lib/$abi" ]; then
                cp -f /tmp/pattng_ref_unzip/lib/$abi/*.so "$ROOT_DIR/V2rayNG/app/libs/$abi/" || true
                # Remove old libgojni.so so only our newly compiled Xray-core is used
                rm -f "$ROOT_DIR/V2rayNG/app/libs/$abi/libgojni.so"
            fi
        done
        rm -rf /tmp/pattng_ref.apk /tmp/pattng_ref_unzip
        echo "✅ Extracted prebuilt C/Rust .so libraries for arm64-v8a & armeabi-v7a!"
    else
        echo "⚠️ Could not find universal APK in latest release, running compile-hevtun.sh..."
        bash compile-hevtun.sh
        cp -r "$ROOT_DIR/libs/." "$ROOT_DIR/V2rayNG/app/libs/"
    fi
fi

# Fetch Psiphon server list if script exists
if [ -f "$ROOT_DIR/fetch-psiphon-servers.sh" ]; then
    bash "$ROOT_DIR/fetch-psiphon-servers.sh" || true
fi

echo "=== [3/6] Installing gomobile & gobind ==="
if ! command -v gomobile &> /dev/null; then
    go install golang.org/x/mobile/cmd/gomobile@latest
    go install golang.org/x/mobile/cmd/gobind@latest
fi

echo "=== [4/6] Compiling Custom libv2ray.aar (with Enhanced ECH Core) for arm64 & armv7a ==="
cd "$ROOT_DIR/AndroidLibXrayLite"
mkdir -p assets data
if [ ! -f "assets/geoip.dat" ]; then
    bash gen_assets.sh download
    cp -v data/*.dat assets/
fi

# Ensure gobind tool directive is registered for Go 1.26+
go get -tool golang.org/x/mobile/cmd/gobind@latest || true
go mod tidy
gomobile init

gomobile bind -v \
    -target=android/arm64,android/arm \
    -androidapi 29 \
    -trimpath \
    -ldflags='-s -w -buildid= -checklinkname=0' \
    -o "$ROOT_DIR/V2rayNG/app/libs/libv2ray.aar" \
    ./

echo "✅ Custom libv2ray.aar built successfully:"
ls -lh "$ROOT_DIR/V2rayNG/app/libs/libv2ray.aar"

echo "=== [5/6] Configuring Gradle Memory Limits for Codespace ==="
cd "$ROOT_DIR/V2rayNG"
echo "sdk.dir=${ANDROID_HOME}" > local.properties

# Pin safe memory limits in V2rayNG/gradle.properties so Codespace daemon never crashes
grep -v "org.gradle.jvmargs" gradle.properties > gradle.properties.tmp || true
mv gradle.properties.tmp gradle.properties
cat << 'EOP' >> gradle.properties

org.gradle.jvmargs=-Xmx2048m -XX:MaxMetaspaceSize=512m -Dfile.encoding=UTF-8
org.gradle.workers.max=2
org.gradle.parallel=false
EOP

echo "=== [6/6] Building V2rayNG APK (armeabi-v7a & arm64-v8a) ==="
chmod +x ./gradlew
./gradlew assembleDebug --no-daemon --max-workers=2

echo ""
echo "=========================================================="
echo "✅ CUSTOM PATTNG APKs BUILT SUCCESSFULLY!"
find "$ROOT_DIR/V2rayNG/app/build/outputs/apk" -name "*.apk" -exec ls -lh {} +
echo "=========================================================="
