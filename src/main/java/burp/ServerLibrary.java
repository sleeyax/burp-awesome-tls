package burp;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;

public interface ServerLibrary extends Library {
    ServerLibrary INSTANCE = Native.load("server." + (Platform.isWindows() ? "dll" : "so"), ServerLibrary.class);

    String StartServer(String address);
    String StopServer();
    void SmokeTest();
}
