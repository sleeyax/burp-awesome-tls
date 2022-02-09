# Awesome TLS
This extension hijacks Burp's HTTP and TLS stack to make it more powerful and less prone to fingerprinting by all kinds of WAFs.
It does this without resorting to hacks, reflection or forked Burp Suite Community code. All Java code only leverages Burp's Extender API.

![screenshot](./docs/screenshot.png)

## How it works
Unfortunately Burp's Extender API is very limited for more advanced use cases like this, so I had to play around with it to make this work. 

Once a request comes in, the extension intercepts it and forwards it to a local HTTPS server that started in the background once loaded/installed.
This server works like a proxy; it forwards the request to the destination, while persisting the original header order and applying a customizable TLS configuration.
Then, the local server forwards the response back to Burp.

Configuration settings and other necessary information like the destination server address are sent to the local server per request by a magic header.
This magic header is stripped from the request before it's forwarded to the destination server, of course.

![diagram](./docs/diagram.png)

Another option would've been to code an upstream proxy server and connect burp to it, but I personally wanted an extension because it's customizable at runtime and more portable. 

## Installation
You'll need to download at least 2 files from the [releases](https://github.com/sleeyax/burp-awesome-tls/releases) page:
The extension itself (.jar) and the local server binary (extension depends on your platform and arch).
Make sure to rename the local server binary to `server.{EXT}`, where `{EXT}` is your platform's extension, e.g `server.dll` and place it somewhere in `PATH` OR at the same location where you downloaded the extension .jar file to.

We use semantic versioning and significant changes to the extension GUI are considered major. 
This way you only need to swap out the server binaries when new minor versions are released.

## Manual build Instructions
This extension was developed with JetBrains IntelliJ (and GoLand) IDE. 
The build instructions below assume you're using the same tools to build.
See [workflows](.github/workflows) for the target programming language versions.

1. Compile the go package within `./src-go/`. Run `cd ./src-go/server && go build -o ../../src/main/resources/{OS}-{ARCH}/server.{EXT} -buildmode=c-shared ./cmd/main.go`, replacing `{OS}-{ARCH}` with your OS and CPU architecture and `{EXT}` with your platform's preferred extension for dynamic C libraries. For example: `linux-x86-64/server.so`. See the [JNA docs](https://github.com/java-native-access/jna/blob/master/www/GettingStarted.md) for more info about supported platforms.
2. Compile the GUI form `SettingsTab.form` into Java code via `Build > Build project`.
3. Build the fat jar with Gradle.

You should now have on jar file, containing all dependencies. 
If you'd rather separate the server binary from the jar, start over from step 1 but instead build the binary to the output directory of the jar.
