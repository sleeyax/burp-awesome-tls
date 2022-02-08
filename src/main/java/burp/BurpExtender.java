package burp;

import com.google.gson.Gson;

import java.io.PrintWriter;
import java.net.URL;
import java.util.Arrays;

public class BurpExtender implements IBurpExtender, IHttpListener, IExtensionStateListener {
    private PrintWriter stdout;
    private PrintWriter stderr;
    private Gson gson;
    private Settings settings;

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    private static final String HEADER_KEY = "Goroundtripperconfig"; // TODO: randomize this key and store it in a config.json file so the go server can retrieve it on startup

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.gson = new Gson();
        this.settings = new Settings(callbacks);

        callbacks.setExtensionName("Awesome TLS");
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.addSuiteTab(new SettingsTab(this.settings));

        new Thread(() -> {
            var err = ServerLibrary.INSTANCE.StartServer(this.settings.getAddress());
            if (!err.equals("")) {
                var isGraceful = err.contains("Server stopped"); // server was stopped gracefully by calling StopServer()
                var out = isGraceful ? this.stdout : this.stderr;
                out.println(err);
                if (!isGraceful) callbacks.unloadExtension(); // fatal error; disable the extension
            }
        }).start();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) return;

        try {
            var url = new URL("https://" + this.settings.getAddress());
            messageInfo.setHttpService(helpers.buildHttpService(url.getHost(), url.getPort(), url.getProtocol()));
        } catch (Exception e) {
            this.stderr.println("Failed to intercept http service: " + e.toString());
            this.callbacks.unloadExtension();
            return;
        }

        var httpService = messageInfo.getHttpService();
        var req = this.helpers.analyzeRequest(messageInfo.getRequest());

        var goConfig = new GoRoundTripperConfig();
        goConfig.Url = httpService.getProtocol() + "://" + httpService.getHost() + ":" + httpService.getPort();
        goConfig.Timeout = this.settings.getTimeout();
        goConfig.TlsFingerprint = this.settings.getTlsFingerprint();
        goConfig.TlsFingerprintFilePath = this.settings.getTlsFingerprintFilePath();
        var goConfigJSON = this.gson.toJson(goConfig);
        this.stdout.println("Using config: " + goConfigJSON);

        var headers = req.getHeaders();
        headers.add(HEADER_KEY + ": " + goConfigJSON);

        messageInfo.setRequest(helpers.buildHttpMessage(headers, Arrays.copyOfRange(messageInfo.getRequest(), req.getBodyOffset(), messageInfo.getRequest().length)));
    }

    @Override
    public void extensionUnloaded() {
        var err = ServerLibrary.INSTANCE.StopServer();
        if (!err.equals("")) {
            this.stderr.println(err);
        }
    }
}
