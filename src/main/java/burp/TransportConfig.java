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

