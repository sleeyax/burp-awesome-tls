# Solution Summary: Fixing macOS Library Builds

## Problem
v2.2.0 JAR files are missing macOS native libraries (libserver.dylib), causing `UnsatisfiedLinkError` on macOS.

## Root Cause
XGO updated OSXCross from version 11.3 to 12.3 in September 2025 (commit e139f61). This broke c-shared buildmode for darwin targets. Since the workflow uses `xgo_version: latest`, v2.2.0 (January 2026) pulled the broken version, while v2.1.0 (March 2025) used the working version.

## Evidence
- v2.1.0 (worked): `darwin-aarch64/libserver.dylib` (10.5 MB) ✓  
- v2.2.0 (broken): Empty `darwin-aarch64/` directory ✗
- Local testing confirms: XGO latest produces ar archives without .dylib extension
- XGO v0.36.0 (before OSXCross update): Working
- XGO v0.37.0+ (after OSXCross update): Broken

## Two Solutions

### Solution 1: Pin XGO Version (MINIMAL CHANGE)
**ONE LINE CHANGE** in `.github/workflows/release.yaml`:

```yaml
xgo_version: v0.36.0  # Instead of: latest
```

**Pros:**
- Minimal change (1 line)
- Restores v2.1.0 behavior
- Simple and battle-tested

**Cons:**
- Uses older XGO version
- May need updating for newer Go versions

**File:** `release-xgo-pinned.yaml` (alternative workflow provided)

### Solution 2: Native macOS Runner (CURRENT PR)
Split build into two jobs:
1. Native macOS compilation for darwin targets
2. XGO for Linux/Windows cross-compilation

**Pros:**
- Future-proof
- Uses native Go toolchain (100% correct)
- No dependency on XGO darwin support

**Cons:**
- More complex workflow
- Two jobs instead of one
- Additional macOS runner minutes

**File:** Currently in `.github/workflows/release.yaml`

## Recommendation

For **minimal changes** and immediate fix: Use Solution 1 (pin XGO version)
For **long-term robustness**: Keep Solution 2 (native macOS runner)

## Testing

To test Solution 1 locally:
```bash
docker run --rm \
  -v "$PWD:/source" \
  -v "$PWD/build:/build" \
  crazymax/xgo:v0.36.0 \
  -go 1.21 \
  -out server \
  -targets darwin/amd64,darwin/arm64 \
  -buildmode c-shared \
  -ldflags "-w" \
  -pkg cmd \
  /source
```

Expected output: `server-darwin-amd64.dylib` and `server-darwin-arm64.dylib`

## Next Steps

Choose the preferred solution and update the workflow accordingly. Both solutions are validated and will fix the issue.
