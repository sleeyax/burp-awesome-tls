package burp;

import java.util.ArrayList;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Awesome TLS");
        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) return;

        var httpService = messageInfo.getHttpService();

        var ignoredHosts = new ArrayList<String>(); // TODO: ignore specific hosts from going through this extension through a setting

        if (!ignoredHosts.contains(httpService.getHost())) {
            // messageInfo.setHttpService(helpers.buildHttpService("127.0.0.1", httpService.getPort(), httpService.getProtocol()));
            messageInfo.setHttpService(helpers.buildHttpService("127.0.0.1", 8887, "http"));
        }
    }
}
