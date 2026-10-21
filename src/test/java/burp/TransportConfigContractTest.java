package burp;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The fixture is also parsed by the Go server's TestTransportConfigContract, so both sides agree on the configuration header format.
 */
class TransportConfigContractTest {
    private static final Path CONTRACT = Path.of("src-go/server/testdata/transport_config.json");

    @Test
    void serializesToContract() throws Exception {
        var config = new TransportConfig();
        config.Host = "example.com:8443";
        config.Scheme = "https";
        config.InterceptProxyAddr = "127.0.0.1:8886";
        config.BurpAddr = "127.0.0.1:8080";
        config.Fingerprint = "chrome_133";
        config.HexClientHello = "1603";
        config.UseInterceptedFingerprint = true;
        config.HttpTimeout = 30;
        config.HeaderOrder = new String[]{"Host", "User-Agent"};
        config.ExternalProxyUrl = "http://user:pass@proxy:3128";

        var expected = JsonParser.parseString(Files.readString(CONTRACT));
        var actual = JsonParser.parseString(new Gson().toJson(config));

        assertEquals(expected, actual);
    }

    @Test
    void contractCoversEveryField() throws Exception {
        var contractKeys = new TreeSet<>(JsonParser.parseString(Files.readString(CONTRACT)).getAsJsonObject().keySet());
        var fields = new TreeSet<String>();
        Arrays.stream(TransportConfig.class.getDeclaredFields())
                .filter(f -> !Modifier.isStatic(f.getModifiers()))
                .map(Field::getName)
                .forEach(fields::add);

        assertEquals(fields, contractKeys);
    }
}
