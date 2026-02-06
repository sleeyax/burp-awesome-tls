# XGO Darwin Build Investigation

## Question
Why doesn't XGO work for building macOS (darwin) libraries with `buildmode: c-shared`?

## Investigation Process

### Test Setup
Ran XGO locally with the exact configuration from the release workflow:
```bash
docker run --rm \
  -v "$PWD:/source" \
  -v "$PWD/build:/build" \
  crazymax/xgo:latest \
  -go 1.21 \
  -out server \
  -targets darwin/amd64,darwin/arm64 \
  -buildmode c-shared \
  -ldflags "-w" \
  -x \
  -pkg cmd \
  /source
```

## Findings

### XGO DOES Generate Darwin Binaries!

XGO successfully compiles darwin binaries, but with **incorrect file names**:

#### What XGO Creates:
- `server-darwin-amd64` (NO extension)
- `server-darwin-arm64` (NO extension)

#### What build.sh Expects:
- `server-darwin-amd64.dylib`
- `server-darwin-arm64.dylib`

### File Type Analysis
```bash
$ file build/server-darwin-*
build/server-darwin-amd64: current ar archive
build/server-darwin-arm64: current ar archive
```

The files are **ar archives**, not proper shared libraries (.dylib files). This indicates XGO's `c-shared` buildmode isn't working correctly for darwin targets.

### XGO Build Output
From the logs, XGO executed:
```
Compiling for darwin/amd64...
+ CC=o64-clang
+ CXX=o64-clang++
+ GOOS=darwin
+ GOARCH=amd64
+ CGO_ENABLED=1
+ go build '--ldflags=  ' -o /build/server-darwin-amd64 ./

Compiling for darwin/arm64...
+ CC=o64-clang
+ CXX=o64-clang++
+ GOOS=darwin
+ GOARCH=arm64
+ CGO_ENABLED=1
+ go build '--ldflags=  ' -o /build/server-darwin-arm64 ./
```

Notice: The `-buildmode c-shared` flag is **NOT** being passed to `go build`!

## Root Cause

XGO's `extension()` function (from `/usr/local/bin/xgo-build` in the container) should add `.dylib` for darwin with c-shared buildmode:

```bash
function extension {
  # ...
  elif [ "$FLAG_BUILDMODE" == "shared" ] || [ "$FLAG_BUILDMODE" == "c-shared" ]; then
    if [ "$1" == "darwin" ]; then
      echo ".dylib"
    fi
  fi
}
```

However, the buildmode flag isn't being properly propagated through XGO's build system, causing:
1. No extension added to filenames
2. Wrong build type (ar archive instead of dylib)

## Solution Options

### Option 1: Fix in Workflow (Post-Process)
Add a step after XGO to rename/fix darwin files:
```yaml
- name: Fix darwin file extensions
  run: |
    cd ./src-go/server/build
    if [ -f "server-darwin-amd64" ]; then
      mv server-darwin-amd64 server-darwin-amd64.dylib
    fi
    if [ -f "server-darwin-arm64" ]; then
      mv server-darwin-arm64 server-darwin-arm64.dylib
    fi
```

**Issue**: Files are still ar archives, not proper dylibs!

### Option 2: Use Native macOS Runner (RECOMMENDED)
Compile darwin libraries natively on macOS runner where Go's c-shared buildmode works correctly:
```yaml
- name: Build macOS libraries
  run: |
    CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
      go build -buildmode=c-shared -ldflags="-w" \
      -o build/server-darwin-amd64.dylib ./cmd
```

This produces proper `.dylib` shared libraries.

## Conclusion

XGO **does** generate darwin binaries, but:
1. They have the wrong file extension (missing `.dylib`)
2. They are the wrong file type (ar archives instead of dylibs)
3. The `-buildmode c-shared` flag isn't being respected

The proper fix is to use a native macOS runner for darwin builds, which has already been implemented in the current PR.
