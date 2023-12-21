package burp;


/**
 * Represents the configuration for a transport.
 */
public class TransportConfig {

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
     * Use intercepted fingerprint from request;
     */
    public Boolean UseInterceptedFingerprint;

    /**
     * The maximum amount of time a dial will wait for a connect to complete.
     * Defaults to [DefaultHttpTimeout].
     */
    public int HttpTimeout;

    /**
     * Specifies the interval between keep-alive probes for an active network connection.
     * Defaults to [DefaultHttpKeepAlive].
     */
    public int HttpKeepAliveInterval;

    /**
     * The maximum amount of time an idle (keep-alive) connection will remain idle before closing itself.
     * Defaults to [DefaultIdleConnTimeout].
     */
    public int IdleConnTimeout;

    /**
     * The maximum amount of time to wait for a TLS handshake.
     * Defaults to [DefaultTLSHandshakeTimeout].
     */
    public int TlsHandshakeTimeout;
}

