package burp;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ExtensionTest {
    private final Settings settings = new InMemoryPreferences().settings();

    private static URL url(String url) throws Exception {
        return new URI(url).toURL();
    }

    @Test
    void buildTransportConfigTargetsRequest() throws Exception {
        settings.setFingerprint("firefox_135");
        var headerOrder = new String[]{"Host", "User-Agent", "Accept"};

        var config = Extension.buildTransportConfig(settings, url("https://example.com/path?q=1"), headerOrder);

        assertEquals("example.com", config.Host);
        assertEquals("https", config.Scheme);
        assertArrayEquals(headerOrder, config.HeaderOrder);
        assertEquals("firefox_135", config.Fingerprint);
    }

    @Test
    void buildTransportConfigKeepsNonDefaultPort() throws Exception {
        var config = Extension.buildTransportConfig(settings, url("https://example.com:8443/"), new String[0]);

        assertEquals("example.com:8443", config.Host);
    }

    @Test
    void buildTransportConfigKeepsIPv6Port() throws Exception {
        var config = Extension.buildTransportConfig(settings, url("http://[::1]:8080/"), new String[0]);

        assertEquals("[::1]:8080", config.Host);
        assertEquals("http", config.Scheme);
    }
}
