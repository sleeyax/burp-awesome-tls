package burp;

public class Settings {
    private final IBurpExtenderCallbacks callbacks;
    private final String address = "Address";
    private final String timeout = "Timeout";
    private final String tlsFingerprint = "TlsFingerprint";
    private final String tlsFingerprintFilePath = "TlsFingerprintFilePath";

    public static final String DEFAULT_ADDRESS = "127.0.0.1:8887";
    public static final String DEFAULT_TIMEOUT = "10";
    public static final String DEFAULT_TLS_FINGERPRINT = "Default";

    public Settings(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.setDefaults();
    }

    private void setDefaults() {
        if (this.read(this.address) == null)
            this.write(this.address, DEFAULT_ADDRESS);

        if (this.read(this.timeout) == null)
            this.write(this.timeout, DEFAULT_TIMEOUT);

        if (this.read(this.tlsFingerprint) == null)
            this.write(this.tlsFingerprint, DEFAULT_TLS_FINGERPRINT);
    }

    public String read(String key, String defaultValue) {
        var value = this.callbacks.loadExtensionSetting(key);
        return value != null ? value : defaultValue;
    }

    public String read(String key) {
       return this.callbacks.loadExtensionSetting(key);
    }

    public void write(String key, String value) {
        this.callbacks.saveExtensionSetting(key, value);
    }

    public String getAddress() {
        return this.read(this.address);
    }

    public void setAddress(String address) {
        this.write(this.address, address);
    }

    public int getTimeout() {
        return Integer.parseInt(this.read(this.timeout));
    }

    public void setTimeout(int timeout) {
        this.write(this.timeout, String.valueOf(timeout));
    }

    public String getTlsFingerprint() {
        return this.read(this.tlsFingerprint);
    }

    public void setTlsFingerprint(String tlsFingerprint) {
        this.write(this.tlsFingerprint, tlsFingerprint);
    }

    public String getTlsFingerprintFilePath() {
        return this.read(this.tlsFingerprintFilePath);
    }

    public void setTlsFingerprintFilePath(String tlsFingerprintFilePath) {
        this.write(this.tlsFingerprintFilePath, tlsFingerprintFilePath);
    }

    public String[] getTlsFingerprints() {
        return new String[]{
                "Default",
                "Chrome 83",
                "Chrome 96",
                "Firefox 56",
                "Firefox 65",
                "iOS 13",
                "iOS 14",
                "Android 11 OkHttp"
        };
    }
}
