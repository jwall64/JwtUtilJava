package org.wallentines.jwt;

import org.wallentines.mdcfg.serializer.Serializer;

public enum KeyUse {

    SIGNING("sig"),
    ENCRYPTION("enc");

    String id;

    KeyUse(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public static KeyUse byId(String name) {
        for (KeyUse use : values()) {
            if (use.id().equals(name)) {
                return use;
            }
        }
        return null;
    }

    public static Serializer<KeyUse> SERIALIZER = Serializer.STRING.flatMap(KeyUse::id, KeyUse::byId);
}
