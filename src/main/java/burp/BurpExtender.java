package burp;

import java.io.PrintWriter;
import java.util.ArrayList;

public class BurpExtender implements IBurpExtender, IHttpListener, IExtensionStateListener {
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IExtensionHelpers helpers;
    private String host;
    private int port;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.helpers = callbacks.getHelpers();
        // TODO: specify host & port in settings
        this.host = "127.0.0.1";
        this.port = 8887;

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

        var ignoredHosts = new ArrayList<String>(); // TODO: ignore specific hosts from going through this extension through a setting

        if (!ignoredHosts.contains(httpService.getHost())) {
            // messageInfo.setHttpService(helpers.buildHttpService("127.0.0.1", httpService.getPort(), httpService.getProtocol()));
            messageInfo.setHttpService(helpers.buildHttpService(this.host, this.port, "http"));
        }
    }

    @Override
    public void extensionUnloaded() {
        var err = ServerLibrary.INSTANCE.StopServer();
        if (!err.equals("")) {
            this.stderr.println(err);
        }
    }
}
