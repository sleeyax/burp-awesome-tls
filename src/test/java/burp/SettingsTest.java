package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SettingsTest {
    private final InMemoryPreferences preferences = new InMemoryPreferences();
    private final Settings settings = preferences.settings();

    @Test
    void returnsAndStoresDefaultsWhenUnset() {
        assertEquals(Settings.DEFAULT_SPOOF_PROXY_ADDRESS, settings.getSpoofProxyAddress());
        assertEquals(Settings.DEFAULT_INTERCEPT_PROXY_ADDRESS, settings.getInterceptProxyAddress());
        assertEquals(Settings.DEFAULT_BURP_PROXY_ADDRESS, settings.getBurpProxyAddress());
        assertEquals(Settings.DEFAULT_TLS_FINGERPRINT, settings.getFingerprint());
        assertEquals(Settings.DEFAULT_HTTP_TIMEOUT, settings.getHttpTimeout());
        assertEquals(Settings.USE_INTERCEPTED_FINGERPRINT, settings.getUseInterceptedFingerprint());
        assertEquals(Settings.DEFAULT_EXTERNAL_PROXY_URL, settings.getExternalProxyUrl());
        assertEquals("", settings.getHexClientHello());

        assertEquals(Settings.DEFAULT_SPOOF_PROXY_ADDRESS, preferences.strings.get("SpoofProxyAddress"));
        assertEquals(Settings.DEFAULT_HTTP_TIMEOUT, preferences.integers.get("HttpTimeout"));
        assertEquals(Settings.USE_INTERCEPTED_FINGERPRINT, preferences.booleans.get("UseInterceptedFingerprint"));
    }

    @Test
    void treatsEmptyStringAsUnset() {
        preferences.strings.put("SpoofProxyAddress", "");

        assertEquals(Settings.DEFAULT_SPOOF_PROXY_ADDRESS, settings.getSpoofProxyAddress());
    }

    @Test
    void persistsWrittenValues() {
        settings.setSpoofProxyAddress("127.0.0.1:9999");
        settings.setInterceptProxyAddress("127.0.0.1:9998");
        settings.setBurpProxyAddress("127.0.0.1:9997");
        settings.setFingerprint("firefox_135");
        settings.setHexClientHello("1603");
        settings.setHttpTimeout(5);
        settings.setUseInterceptedFingerprint(true);
        settings.setExternalProxyUrl("http://proxy:3128");

        var reloaded = preferences.settings();
        assertEquals("127.0.0.1:9999", reloaded.getSpoofProxyAddress());
        assertEquals("127.0.0.1:9998", reloaded.getInterceptProxyAddress());
        assertEquals("127.0.0.1:9997", reloaded.getBurpProxyAddress());
        assertEquals("firefox_135", reloaded.getFingerprint());
        assertEquals("1603", reloaded.getHexClientHello());
        assertEquals(5, reloaded.getHttpTimeout());
        assertEquals(true, reloaded.getUseInterceptedFingerprint());
        assertEquals("http://proxy:3128", reloaded.getExternalProxyUrl());
    }

    @Test
    void toTransportConfigCopiesSettings() {
        settings.setFingerprint("chrome_133");
        settings.setHexClientHello("1603");
        settings.setHttpTimeout(12);
        settings.setUseInterceptedFingerprint(true);
        settings.setInterceptProxyAddress("127.0.0.1:1111");
        settings.setBurpProxyAddress("127.0.0.1:2222");
        settings.setExternalProxyUrl("http://proxy:3128");

        var config = settings.toTransportConfig();

        assertEquals("chrome_133", config.Fingerprint);
        assertEquals("1603", config.HexClientHello);
        assertEquals(12, config.HttpTimeout);
        assertEquals(true, config.UseInterceptedFingerprint);
        assertEquals("127.0.0.1:1111", config.InterceptProxyAddr);
        assertEquals("127.0.0.1:2222", config.BurpAddr);
        assertEquals("http://proxy:3128", config.ExternalProxyUrl);
        assertNull(config.Host);
        assertNull(config.Scheme);
        assertNull(config.HeaderOrder);
    }
}
