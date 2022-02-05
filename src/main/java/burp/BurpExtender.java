package burp;

import com.google.gson.Gson;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;

public class BurpExtender implements IBurpExtender, IHttpListener, IExtensionStateListener {
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IExtensionHelpers helpers;
    private String host;
    private int port;
    private Gson gson;
    private static final String HEADER_KEY = "GoRoundTripperConfig";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.helpers = callbacks.getHelpers();
        // TODO: specify host & port in settings
        this.host = "127.0.0.1";
        this.port = 8887;
        this.gson = new Gson();

        callbacks.setExtensionName("Awesome TLS");
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);

        new Thread(() -> {
            var err = ServerLibrary.INSTANCE.StartServer(this.host + ":" + this.port);
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

        var httpService = messageInfo.getHttpService();
        var req = this.helpers.analyzeRequest(messageInfo.getRequest());

        var goConfig = new GoRoundTripperConfig(); // TODO: set config values from UI
        goConfig.Url = httpService.getProtocol() + "://" + httpService.getHost() + ":" + httpService.getPort();
        var goConfigJSON = this.gson.toJson(goConfig);
        this.stdout.println("Config changed: " + goConfigJSON);

        var headers = req.getHeaders();
        headers.add(HEADER_KEY + ": " + goConfigJSON);

        messageInfo.setRequest(helpers.buildHttpMessage(headers, Arrays.copyOfRange(messageInfo.getRequest(), req.getBodyOffset(), messageInfo.getRequest().length)));
        messageInfo.setHttpService(helpers.buildHttpService(this.host, this.port, "https"));
    }

    @Override
    public void extensionUnloaded() {
        var err = ServerLibrary.INSTANCE.StopServer();
        if (!err.equals("")) {
            this.stderr.println(err);
        }
    }
}
