package burp;


/**
 * Represents the configuration for transport.
 */
public class TransportConfig {
    /*
     * Hostname.
     */
    public String Host;

    /**
     * Protocol scheme (HTTP or HTTPS).
     */
    public String Scheme;

    /**
     * Intercept ClientHello Proxy Address.
     */
    public String InterceptProxyAddr;
    /**
     * Burp Proxy Address.
     */
    public String BurpAddr;

    /**
     * The TLS fingerprint to use.
     */
    public String Fingerprint;

    /*
     * Hexadecimal Client Hello
     */
    public String HexClientHello;

    /*
     * Use intercepted fingerprint from request;
     */
    public Boolean UseInterceptedFingerprint;

    /**
     * The maximum amount of time a dial will wait for a connect to complete.
     * Defaults to [DefaultHttpTimeout].
     */
    public int HttpTimeout;
}

