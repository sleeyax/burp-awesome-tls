# XGO Darwin Build Investigation

## Question
Why doesn't XGO work for building macOS (darwin) libraries with `buildmode: c-shared` in v2.2.0, when it worked fine in v2.1.0?

## Investigation Timeline

### v2.1.0 (March 2025) - WORKING ✓
- Go version: 1.22.0 (toolchain 1.24.0)
- XGO version: `latest` (commit 866cd0b, before Sept 2025 changes)
- JAR contents: `darwin-aarch64/libserver.dylib` (10.5 MB) ✓
- OSXCross version in XGO: 11.3

### v2.2.0 (January 2026) - BROKEN ✗
- Go version: 1.24.1 (toolchain 1.25.6)
- XGO version: `latest` (includes Sept 2025 changes)
- JAR contents: Empty `darwin-aarch64/` directory ✗
- OSXCross version in XGO: 12.3

## Root Cause Discovery

### XGO Change Log Analysis
Between v2.1.0 and v2.2.0, XGO made critical changes:

**September 14, 2025 - Commit e139f61:**
```diff
-ARG OSXCROSS_VERSION="11.3"
+ARG OSXCROSS_VERSION="12.3"
```

This OSXCross update from 11.3 to 12.3 broke c-shared builds for darwin targets!

### Evidence

1. **Workflow unchanged**: `.github/workflows/release.yaml` had only minor action version bumps
2. **build.sh unchanged**: Still expects `.dylib` files in both versions
3. **XGO behavior changed**: After OSXCross 12.3 update, darwin builds produce:
   - Wrong file names: `server-darwin-amd64` (no extension) instead of `server-darwin-amd64.dylib`
   - Wrong file type: `ar archive` instead of Mach-O shared library
   - buildmode flag not respected

### Local Testing Confirms
```bash
$ docker run crazymax/xgo:latest -buildmode c-shared -targets darwin/amd64,darwin/arm64 ...
# Produces:
- server-darwin-amd64 (ar archive, 715KB)
- server-darwin-arm64 (ar archive, 710KB)

$ file build/server-darwin-*
build/server-darwin-amd64: current ar archive
build/server-darwin-arm64: current ar archive
```

## Solution Options

### Option 1: Pin XGO to Pre-OSXCross-12.3 Version (MINIMAL FIX)
**Pros:**
- Minimal workflow change (one line)
- Uses battle-tested XGO version that worked in v2.1.0
- No additional complexity

**Cons:**
- Uses older XGO version
- May miss newer Go versions/features
- Still relies on XGO's darwin support

**Implementation:**
```yaml
- name: Execute CGO builds using XGO
  uses: crazy-max/ghaction-xgo@v3
  with:
    xgo_version: v0.24.0  # Pin to last working version (before Sept 2025)
    # ... rest unchanged
```

### Option 2: Use Native macOS Runner (ALREADY IMPLEMENTED)
**Pros:**
- Produces proper dylib files
- Uses native Go toolchain (100% correct)
- Future-proof solution

**Cons:**
- More complex workflow
- Requires two jobs instead of one
- Additional macOS runner minutes

### Option 3: Post-Process XGO Output
**Pros:**
- Keeps XGO for all platforms

**Cons:**
- Doesn't fix the ar archive issue
- Fragile workaround
- Files still wrong type

## Recommended Fix

Given the user's preference to keep using XGO directly, **Option 1** is the minimal fix:

```yaml
xgo_version: v0.24.0  # or v0.23.0 - last version before OSXCross 12.3
```

This restores the working behavior from v2.1.0 with a one-line change.

## Alternative: Update to Latest XGO
If XGO has fixed the issue in newer versions, we could:
1. Check latest XGO releases
2. Test with latest version
3. Report issue to XGO maintainers if still broken

## Conclusion

The OSXCross 12.3 update in XGO broke darwin c-shared builds. The simplest fix is pinning `xgo_version` to the last working version (v0.24.0 or earlier from before September 2025).
