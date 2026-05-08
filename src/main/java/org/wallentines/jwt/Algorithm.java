package org.wallentines.jwt;

import org.wallentines.mdcfg.serializer.Serializer;

public enum Algorithm {

    NONE("none", null, null),

    HS256("HS256", KeyType.OCTET_SEQUENCE, KeyUse.SIGNING),
    HS384("HS384", KeyType.OCTET_SEQUENCE, KeyUse.SIGNING),
    HS512("HS512", KeyType.OCTET_SEQUENCE, KeyUse.SIGNING),

    RS256("RS256", KeyType.RSA, KeyUse.SIGNING),
    RS384("RS384", KeyType.RSA, KeyUse.SIGNING),
    RS512("RS512", KeyType.RSA, KeyUse.SIGNING),

    ES256("ES256", KeyType.ELLIPTIC_CURVE, KeyUse.SIGNING),
    ES384("ES384", KeyType.ELLIPTIC_CURVE, KeyUse.SIGNING),
    ES512("ES512", KeyType.ELLIPTIC_CURVE, KeyUse.SIGNING),

    PS256("PS256", KeyType.RSA, KeyUse.SIGNING),
    PS384("PS384", KeyType.RSA, KeyUse.SIGNING),
    PS512("PS512", KeyType.RSA, KeyUse.SIGNING),

    RSA1_5("RSA1_5", KeyType.RSA, KeyUse.ENCRYPTION),
    RSA_OAEP("RSA-OAEP", KeyType.RSA, KeyUse.ENCRYPTION),
    RSA_OAEP_256("RSA-OAEP-256", KeyType.RSA, KeyUse.ENCRYPTION),

    A128KW("A128KW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    A192KW("A192KW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    A256KW("A256KW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    
    DIRECT("dir", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    
    ECDH_ES("ECDH-ES", KeyType.ELLIPTIC_CURVE, KeyUse.ENCRYPTION),
    ECDH_ES_A128KW("ECDH-ES+A128KW", KeyType.ELLIPTIC_CURVE, KeyUse.ENCRYPTION),
    ECDH_ES_A192KW("ECDH-ES+A192KW", KeyType.ELLIPTIC_CURVE, KeyUse.ENCRYPTION),
    ECDH_ES_A256KW("ECDH-ES+A256KW", KeyType.ELLIPTIC_CURVE, KeyUse.ENCRYPTION),

    A128GCMKW("A128GCMKW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    A192GCMKW("A192GCMKW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    A256GCMKW("A256GCMKW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),

    PBES2_HS256_A128KW("PBES2-HS256+A128KW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    PBES2_HS384_A192KW("PBES2-HS384+A192KW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION),
    PBES2_HS512_A256KW("PBES2-HS512+A256KW", KeyType.OCTET_SEQUENCE, KeyUse.ENCRYPTION);


    private String id;
    private KeyType keyType;
    private KeyUse keyUse;

    Algorithm(String name, KeyType keyType, KeyUse keyUse) {
        this.id = name;
        this.keyType = keyType;
        this.keyUse = keyUse;
    }

    public String id() {
        return id;
    }

    public KeyType type() {
        return keyType;
    }

    public KeyUse use() {
        return keyUse;
    }

    public static Algorithm byId(String id) {
        for (Algorithm alg : values()) {
            if (alg.id().equals(id)) {
                return alg;
            }
        }
        return null;
    }

    public static Serializer<Algorithm> SERIALIZER = Serializer.STRING.flatMap(Algorithm::id, Algorithm::byId);

}
