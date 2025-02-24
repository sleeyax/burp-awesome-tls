package burp;

import java.io.PrintWriter;

public class Settings {
    private final IBurpExtenderCallbacks callbacks;

    private final String spoofProxyAddress = "SpoofProxyAddress";
    private final String interceptProxyAddress = "InterceptProxyAddress";
    private final String burpProxyAddress = "BurpProxyAddress";
    private final String fingerprint = "Fingerprint";
    private final String hexClientHello = "HexClientHello";
    private final String useInterceptedFingerprint = "UseInterceptedFingerprint";
    private final String httpTimeout = "HttpTimeout";

    public static final String DEFAULT_SPOOF_PROXY_ADDRESS = "127.0.0.1:8887";
    public static final String DEFAULT_INTERCEPT_PROXY_ADDRESS = "127.0.0.1:8886";
    public static final String DEFAULT_BURP_PROXY_ADDRESS = "127.0.0.1:8080";
    public static final String DEFAULT_HTTP_TIMEOUT = "30";
    public static final String DEFAULT_TLS_FINGERPRINT = "default";

    public Settings(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.setDefaults();
    }

    private void setDefaults() {
       if (this.read(this.spoofProxyAddress) == "" || this.read(this.spoofProxyAddress) == null) {
           this.write(this.spoofProxyAddress, DEFAULT_SPOOF_PROXY_ADDRESS);
       }

       if (this.read(this.interceptProxyAddress) == "" || this.read(this.interceptProxyAddress) == null) {
           this.write(this.interceptProxyAddress, DEFAULT_INTERCEPT_PROXY_ADDRESS);
       }

       if (this.read(this.burpProxyAddress) == "" || this.read(this.burpProxyAddress) == null) {
           this.write(this.burpProxyAddress, DEFAULT_BURP_PROXY_ADDRESS);
       }

        if (this.read(this.fingerprint) == null) {
            this.write(this.fingerprint, DEFAULT_TLS_FINGERPRINT);
        }

        if (this.read(this.httpTimeout) == null) {
            this.write(this.httpTimeout, DEFAULT_HTTP_TIMEOUT);
        }
    }

    public String read(String key) {
       return this.callbacks.loadExtensionSetting(key);
    }

    public void write(String key, String value) {
        this.callbacks.saveExtensionSetting(key, value);
    }

    public String getSpoofProxyAddress() {
        return this.read(this.spoofProxyAddress);
    }

    public void setSpoofProxyAddress(String spoofProxyAddress) {
        this.write(this.spoofProxyAddress, spoofProxyAddress);
    }

    public String getInterceptProxyAddress() {
        return this.read(this.interceptProxyAddress);
    }

    public void setInterceptProxyAddress(String interceptProxyAddress) {
        this.write(this.interceptProxyAddress, interceptProxyAddress);
    }

    public String getBurpProxyAddress() {
        return this.read(this.burpProxyAddress);
    }

    public void setBurpProxyAddress(String burpProxyAddress) {
        this.write(this.burpProxyAddress, burpProxyAddress);
    }

    public Boolean getUseInterceptedFingerprint() {
        return Boolean.parseBoolean(this.read(this.useInterceptedFingerprint));
    }

    public void setUseInterceptedFingerprint(Boolean useInterceptedFingerprint) {
        this.write(this.useInterceptedFingerprint, String.valueOf(useInterceptedFingerprint));
    }

    public int getHttpTimeout() {
        return Integer.parseInt(this.read(this.httpTimeout));
    }

    public void setHttpTimeout(int httpTimeout) {
        this.write(this.httpTimeout, String.valueOf(httpTimeout));
    }

    public String getFingerprint() { return this.read(this.fingerprint); }

    public void setFingerprint(String fingerprint) {
        this.write(this.fingerprint, fingerprint);
    }

    public String getHexClientHello() { return this.read(this.hexClientHello); }

    public void setHexClientHello(String hexClientHello) { this.write(this.hexClientHello, hexClientHello); }

    public String[] getFingerprints() {
        return new String[]{
               "chrome_103",
                "chrome_112",
                "chrome_116_PSK",
                "chrome_116_PSK_PQ",
                "firefox_133",
        };
    }
}
