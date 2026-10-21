package burp;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Loads the Go server library through JNA, so it needs the native library for this platform on the classpath.
 * Run it with {@code ./gradlew nativeTest}.
 */
@Tag("native")
class ServerLibraryTest {
    @Test
    void smokeTest() {
        ServerLibrary.INSTANCE.SmokeTest();
    }

    @Test
    void listsFingerprints() {
        var fingerprints = ServerLibrary.INSTANCE.GetFingerprints().split("\n");

        assertEquals("default", fingerprints[0]);
        assertTrue(fingerprints.length > 1, "expected fingerprints besides the default");
    }

    @Test
    void startsServesAndStopsServer() throws Exception {
        var address = "127.0.0.1:" + freePort();
        var serverResult = CompletableFuture.supplyAsync(() -> ServerLibrary.INSTANCE.StartServer(address));

        var client = HttpClient.newBuilder().sslContext(trustAllContext()).build();
        var request = HttpRequest.newBuilder(URI.create("https://" + address + "/")).build();
        var response = sendWhenReady(client, request, serverResult);

        assertEquals(500, response.statusCode());
        assertTrue(response.body().startsWith("Awesome TLS error"), response.body());

        assertEquals("", ServerLibrary.INSTANCE.StopServer());
        serverResult.get(10, TimeUnit.SECONDS);
    }

    private static int freePort() throws Exception {
        try (var socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static HttpResponse<String> sendWhenReady(HttpClient client, HttpRequest request, CompletableFuture<String> serverResult) throws Exception {
        var deadline = Instant.now().plus(Duration.ofSeconds(10));
        while (true) {
            try {
                return client.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (ConnectException e) {
                if (serverResult.isDone()) {
                    fail("server exited before accepting connections: " + serverResult.get());
                }
                if (Instant.now().isAfter(deadline)) {
                    throw e;
                }
                Thread.sleep(50);
            }
        }
    }

    // The server presents its self-signed CA for awesometls/localhost, so neither the chain nor the 127.0.0.1 hostname would verify.
    private static SSLContext trustAllContext() throws Exception {
        var trustAll = new X509ExtendedTrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        var context = SSLContext.getInstance("TLS");
        context.init(null, new javax.net.ssl.TrustManager[]{trustAll}, null);
        return context;
    }
}
