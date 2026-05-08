package org.wallentines.jwt;

public enum CryptAlgorithm {

    A128CBC_HS256("A128CBC-HS256", 32, 16),
    A192CBC_HS384("A192CBC-HS384", 48, 16),
    A256CBC_HS512("A256CBC-HS512", 64, 16),

    A128GCM("A128GCM", 16, 12),
    A192GCM("A192GCM", 24, 12),
    A256GCM("A256GCM", 32, 12);

    private final String id;
    private final int keyLength;
    private final int ivLength;

    CryptAlgorithm(String id, int keyLength, int ivLength) {
        this.id = id;
        this.keyLength = keyLength;
        this.ivLength = ivLength;
    }

    public String id() {
        return id;
    }

    public int keyLength() {
        return keyLength;
    }

    public int ivLength() {
        return ivLength;
    }

    public static CryptAlgorithm byId(String id) {
        for (CryptAlgorithm alg : values()) {
            if (alg.id().equals(id)) {
                return alg;
            }
        }
        return null;
    }
}
