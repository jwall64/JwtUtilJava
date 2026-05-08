package org.wallentines.jwt;

import org.wallentines.mdcfg.serializer.Serializer;

public enum KeyOperation {

    SIGN("sign"),
    VERIFY("verify"),
    ENCRYPT("encrypt"),
    DECRYPT("decrypt"),
    WRAP_KEY("wrapKey"),
    UNWRAP_KEY("unwrapKey"),
    DERIVE_KEY("deriveKey"),
    DERIVE_BITS("deriveBits");

    private String id;

    KeyOperation(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public static KeyOperation byId(String name) {
        for (KeyOperation op : values()) {
            if (op.id().equals(name)) {
                return op;
            }
        }
        return null;
    }

    public static Serializer<KeyOperation> SERIALIZER = Serializer.STRING.flatMap(KeyOperation::id, KeyOperation::byId);
}
