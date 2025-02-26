package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.proxy.http.*;
import com.google.gson.Gson;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class Extension implements BurpExtension {
    private MontoyaApi api;
    private Gson gson;
    private Settings settings;

    private static final String HEADER_KEY = "Awesometlsconfig";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.gson = new Gson();
        this.settings = new Settings(api);

        api.extension().setName("Awesome TLS");
        api.extension().registerUnloadingHandler(() -> {
            var err = ServerLibrary.INSTANCE.StopServer();
            if (!err.isEmpty()) {
                api.logging().logToError(err);
            }
        });
        api.userInterface().registerSuiteTab("Awesome TLS", new SettingsTab(settings).getUI());
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                return processHttpRequest(interceptedRequest);
            }

            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            }
        });
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                return processHttpResponse(interceptedResponse);
            }

            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }
        });

        new Thread(() -> {
            var err = ServerLibrary.INSTANCE.StartServer(settings.getSpoofProxyAddress());
            if (!err.isEmpty()) {
                api.logging().logToError(err);
                var isGraceful = err.contains("Server stopped") || err.contains("address already in use");
                if (!isGraceful) {
                    api.extension().unload(); // fatal error; disable the extension
                }
            }
        }).start();
    }

    private ProxyRequestToBeSentAction processHttpRequest(InterceptedRequest request) {
        try {
            var requestURL = new URL(request.url());

            var headerOrder = new String[request.headers().size()];
            for (var i = 0; i < request.headers().size(); i++) {
                headerOrder[i] = request.headers().get(i).name();
            }

            var transportConfig = settings.toTransportConfig();
            transportConfig.Host = requestURL.getHost();
            transportConfig.Scheme = requestURL.getProtocol();
            transportConfig.HeaderOrder = headerOrder;

            var goConfigJSON = gson.toJson(transportConfig);
            var url = new URL("https://" + settings.getSpoofProxyAddress());
            var httpService = HttpService.httpService(url.getHost(), url.getPort(), Objects.equals(url.getProtocol(), "https"));
            var nextRequest = request.withService(httpService).withAddedHeader(HEADER_KEY, goConfigJSON);

            return ProxyRequestToBeSentAction.continueWith(nextRequest);
        } catch (Exception e) {
            api.logging().logToError("Http request error: " + e);
            return null;
        }
    }

    private ProxyResponseToBeSentAction processHttpResponse(InterceptedResponse proxyMessage) {
        if (proxyMessage.request().httpService().host().equals("awesome-tls-error")) {
            api.logging().logToError("Http response error: " + new String(proxyMessage.body().getBytes(), StandardCharsets.UTF_8));
        }

        return ProxyResponseToBeSentAction.continueWith(proxyMessage);
    }
}
