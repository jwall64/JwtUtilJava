package org.wallentines.jwt;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.wallentines.mdcfg.ConfigSection;
import org.wallentines.mdcfg.serializer.Serializer;

public class KeySet implements KeySupplier {

    private final List<JsonWebKey> keys;
    private final Map<String, Integer> keyMap;

    public KeySet(List<JsonWebKey> keys) {
        this.keys = keys;
        this.keyMap = keys.stream().filter(k -> k.keyId() != null).collect(Collectors.toMap(JsonWebKey::keyId, keys::indexOf));
    }

    public JsonWebKey getKey(String keyId) {
        Integer index = keyMap.get(keyId);
        if (index == null) return null;
        return keys.get(index);
    }

    public JsonWebKey getKey(ConfigSection header) {
        if (header.hasString("kid")) {
            return getKey(header.getString("kid"));
        }
        return null;
    }

     public List<JsonWebKey> keys() {
        return keys;
     }

    public static Serializer<KeySet> SERIALIZER = JsonWebKey.SERIALIZER.listOf().mapToList().fieldOf("keys")
            .flatMap(KeySet::keys, KeySet::new);


}
