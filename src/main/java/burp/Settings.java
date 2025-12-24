package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

public class Settings {
    private final Preferences storage;

    private final String spoofProxyAddress = "SpoofProxyAddress";
    private final String interceptProxyAddress = "InterceptProxyAddress";
    private final String burpProxyAddress = "BurpProxyAddress";
    private final String fingerprint = "Fingerprint";
    private final String hexClientHello = "HexClientHello";
    private final String useInterceptedFingerprint = "UseInterceptedFingerprint";
    private final String httpTimeout = "HttpTimeout";
    private final String debug = "Debug";

    public static final String DEFAULT_SPOOF_PROXY_ADDRESS = "127.0.0.1:8887";
    public static final String DEFAULT_INTERCEPT_PROXY_ADDRESS = "127.0.0.1:8886";
    public static final String DEFAULT_BURP_PROXY_ADDRESS = "127.0.0.1:8080";
    public static final Integer DEFAULT_HTTP_TIMEOUT = 30;
    public static final String DEFAULT_TLS_FINGERPRINT = "default";
    public static final Boolean USE_INTERCEPTED_FINGERPRINT = false;
    public static final Boolean DEFAULT_DEBUG = false;

    public Settings(MontoyaApi api) {
        this.storage = api.persistence().preferences();
    }

    public String read(String key, String defaultValue) {
        var value = this.storage.getString(key);
        if (value == null || value.isEmpty()) {
            this.write(key, defaultValue);
            return defaultValue;
        }
        return value;
    }

    public Boolean read(String key, Boolean defaultValue) {
        var value = this.storage.getBoolean(key);
        if (value == null) {
            this.storage.setBoolean(key, defaultValue);
            return defaultValue;
        }
        return value;
    }

    public Integer read(String key, Integer defaultValue) {
        var value = this.storage.getInteger(key);
        if (value == null) {
            this.storage.setInteger(key, defaultValue);
            return defaultValue;
        }
        return value;
    }

    public void write(String key, String value) {
        this.storage.setString(key, value);
    }

    public void write(String key, Boolean value) {
        this.storage.setBoolean(key, value);
    }

    public void write(String key, Integer value) {
        this.storage.setInteger(key, value);
    }

    public Boolean getDebug() {
        return this.read(this.debug, DEFAULT_DEBUG);
    }

    public void setDebug(Boolean debug) {
        this.write(this.debug, debug);
    }

    public String getSpoofProxyAddress() {
        return this.read(this.spoofProxyAddress, DEFAULT_SPOOF_PROXY_ADDRESS);
    }

    public void setSpoofProxyAddress(String spoofProxyAddress) {
        this.write(this.spoofProxyAddress, spoofProxyAddress);
    }

    public String getInterceptProxyAddress() {
        return this.read(this.interceptProxyAddress, DEFAULT_INTERCEPT_PROXY_ADDRESS);
    }

    public void setInterceptProxyAddress(String interceptProxyAddress) {
        this.write(this.interceptProxyAddress, interceptProxyAddress);
    }

    public String getBurpProxyAddress() {
        return this.read(this.burpProxyAddress, DEFAULT_BURP_PROXY_ADDRESS);
    }

    public void setBurpProxyAddress(String burpProxyAddress) {
        this.write(this.burpProxyAddress, burpProxyAddress);
    }

    public Boolean getUseInterceptedFingerprint() {
        return this.read(this.useInterceptedFingerprint, USE_INTERCEPTED_FINGERPRINT);
    }

    public void setUseInterceptedFingerprint(Boolean useInterceptedFingerprint) {
        this.write(this.useInterceptedFingerprint, useInterceptedFingerprint);
    }

    public int getHttpTimeout() {
        return this.read(this.httpTimeout, DEFAULT_HTTP_TIMEOUT);
    }

    public void setHttpTimeout(Integer httpTimeout) {
        this.write(this.httpTimeout, httpTimeout);
    }

    public String getFingerprint() {
        return this.read(this.fingerprint, DEFAULT_TLS_FINGERPRINT);
    }

    public void setFingerprint(String fingerprint) {
        this.write(this.fingerprint, fingerprint);
    }

    public String getHexClientHello() {
        return this.read(this.hexClientHello, "");
    }

    public void setHexClientHello(String hexClientHello) {
        this.write(this.hexClientHello, hexClientHello);
    }

    public String[] getFingerprints() {
        return ServerLibrary.INSTANCE.GetFingerprints().split("\n");
    }

    public TransportConfig toTransportConfig() {
        var transportConfig = new TransportConfig();
        transportConfig.Fingerprint = this.getFingerprint();
        transportConfig.HexClientHello = this.getHexClientHello();
        transportConfig.HttpTimeout = this.getHttpTimeout();
        transportConfig.UseInterceptedFingerprint = this.getUseInterceptedFingerprint();
        transportConfig.BurpAddr = this.getBurpProxyAddress();
        transportConfig.InterceptProxyAddr = this.getInterceptProxyAddress();
        transportConfig.Debug = this.getDebug();
        return transportConfig;
    }
}
