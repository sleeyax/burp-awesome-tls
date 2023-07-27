package burp;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;

public interface ServerLibrary extends Library {
    ServerLibrary INSTANCE = Native.load((Platform.isMac() ? "lib" : "") +  "server." + (Platform.isWindows() ? "dll" : Platform.isMac() ? "dylib" : "so"), ServerLibrary.class);

    String StartServer(String interceptProxyAddress, String burpProxyAddress, String emulateProxyAddress);
    String StopServer();
    void SmokeTest();
}
