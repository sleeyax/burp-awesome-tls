package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Burp's preference store backed by in-memory maps, for the value types {@link Settings} uses.
 */
final class InMemoryPreferences {
    final Map<String, String> strings = new HashMap<>();
    final Map<String, Boolean> booleans = new HashMap<>();
    final Map<String, Integer> integers = new HashMap<>();
    final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);

    InMemoryPreferences() {
        var preferences = mock(Preferences.class);
        when(api.persistence().preferences()).thenReturn(preferences);

        when(preferences.getString(anyString())).thenAnswer(i -> strings.get(i.<String>getArgument(0)));
        doAnswer(i -> strings.put(i.getArgument(0), i.getArgument(1))).when(preferences).setString(anyString(), anyString());
        when(preferences.getBoolean(anyString())).thenAnswer(i -> booleans.get(i.<String>getArgument(0)));
        doAnswer(i -> booleans.put(i.getArgument(0), i.getArgument(1))).when(preferences).setBoolean(anyString(), anyBoolean());
        when(preferences.getInteger(anyString())).thenAnswer(i -> integers.get(i.<String>getArgument(0)));
        doAnswer(i -> integers.put(i.getArgument(0), i.getArgument(1))).when(preferences).setInteger(anyString(), anyInt());
    }

    Settings settings() {
        return new Settings(api);
    }
}
