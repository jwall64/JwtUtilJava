package org.wallentines.jwt;

import org.wallentines.mdcfg.serializer.Serializer;

public enum KeyType {

    ELLIPTIC_CURVE("EC"),
    RSA("RSA"),
    OCTET_SEQUENCE("oct");

    private String id;

    KeyType(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public static KeyType byId(String name) {
        for (KeyType type : values()) {
            if (type.id().equals(name)) {
                return type;
            }
        }
        return null;
    }

    public static Serializer<KeyType> SERIALIZER = Serializer.STRING.flatMap(KeyType::id, KeyType::byId);

}
