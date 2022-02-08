# Awesome TLS
Fixes Burp Suite's horrible TLS stack.

## Build Instructions
This extension was developed with JetBrains IntelliJ IDE. 
These build instructions assume you're using it too.

1. Compile the go package within `./src-go/`. See [go-src/server](./src-go/server) for build instructions.
2. Compile the GUI form `SettingsTab.form` into Java code via `Build > Build project`.
3. Build the jar with Gradle.
