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
     * The maximum amount of time to wait for an HTTP response.
     */
    public int HttpTimeout;

    /**
     * the order of headers to be sent in the request.
     */
    public String[] HeaderOrder;
}
