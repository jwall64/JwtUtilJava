package org.wallentines.jwt;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import org.wallentines.jwt.impl.KeyValues;
import org.wallentines.mdcfg.ConfigSection;
import org.wallentines.mdcfg.Tuples;
import org.wallentines.mdcfg.serializer.ObjectSerializer;
import org.wallentines.mdcfg.serializer.SerializeResult;
import org.wallentines.mdcfg.serializer.Serializer;

public record JsonWebKey(Meta meta, Value value) implements KeySupplier {


    public record Meta(KeyUse use, EnumSet<KeyOperation> operations, Algorithm algorithm, String keyId, URI x5u, List<String> x5c, String x5t, String x5tS256) {

        public static Serializer<Meta> SERIALIZER = ObjectSerializer.create(
                KeyUse.SERIALIZER.entry("use", Meta::use).optional(),
                KEY_OPS_SERIALIZER.entry("key_ops", Meta::operations).optional(),
                Algorithm.SERIALIZER.entry("alg", Meta::algorithm).optional(),
                Serializer.STRING.entry("kid", Meta::keyId).optional(),
                URI_SERIALIZER.entry("x5u", Meta::x5u).optional(),
                Serializer.STRING.listOf().mapToList().entry("x5c", Meta::x5c).optional(),
                Serializer.STRING.entry("x5t", Meta::x5t).optional(),
                Serializer.STRING.entry("x5t#S256", Meta::x5tS256).optional(),
                Meta::new
        );
    }

    public interface Value { 
        KeyType type();
    }

    public KeyType type() {
        return value.type();
    }

    public KeyUse use() {
        return meta.use();
    }

    public EnumSet<KeyOperation> operations() {
        return meta.operations();
    }

    public Algorithm algorithm() {
        return meta.algorithm();
    }

    public String keyId() {
        return meta.keyId();
    }

    public boolean mayUseFor(KeyUse use, boolean nullBehavior) {
        if(meta.use() == null) return nullBehavior;
        return meta.use() == use;
    }

    public boolean mayUseOp(KeyOperation op, boolean nullBehavior) {
        if(meta.operations() == null) return nullBehavior;
        return meta.operations().contains(op);
    }

    public boolean mayUseAlg(Algorithm alg, boolean nullBehavior) {
        if(meta.algorithm() == null) return nullBehavior;
        return meta.algorithm() == alg;
    }

    @Override
    public JsonWebKey getKey(ConfigSection header) {
        return this;
    }


    private static Serializer<URI> URI_SERIALIZER = Serializer.STRING.map(uri -> SerializeResult.success(uri.toString()), uri -> {
        try {
            return SerializeResult.success(URI.create(uri));
        } catch (Exception e) {
            return SerializeResult.failure("Invalid URI: " + uri, e);
        }
    });

    private static Serializer<EnumSet<KeyOperation>> KEY_OPS_SERIALIZER = KeyOperation.SERIALIZER.listOf().mapToList().<EnumSet<KeyOperation>>map(
        set -> {
            List<KeyOperation> list = new ArrayList<>();
            set.forEach(list::add);
            return SerializeResult.success(list);
        },
        list -> {
            EnumSet<KeyOperation> set = EnumSet.noneOf(KeyOperation.class);
            for(KeyOperation op : list) {
                if(set.contains(op)) return SerializeResult.failure("Duplicate key operation: " + op);
                set.add(op);
            }
            return SerializeResult.success(set);
        }
    );

    public static Serializer<JsonWebKey> SERIALIZER = 
        Meta.SERIALIZER.and(KeyValues.SERIALIZER).flatMap(
            key -> new Tuples.T2<>(key.meta(), key.value()),
            (t2) -> new JsonWebKey(t2.p1, t2.p2)
        );

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private KeyUse use;
        private List<KeyOperation> operations;
        private Algorithm algorithm;
        private String keyId;
        private URI x5u;
        private List<String> x5c;
        private String x5t;
        private String x5tS256;
        private int keySize;
        private EcCurve ecCurve;

        public Builder() {
            this.operations = new ArrayList<>();
            this.x5c = new ArrayList<>();
        }

        public Builder withUse(KeyUse use) {
            this.use = use;
            return this;
        }

        public Builder withOperation(KeyOperation operation) {
            this.operations.add(operation);
            return this;
        }

        public Builder withAlgorithm(Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder withKeyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder withX5u(URI x5u) {
            this.x5u = x5u;
            return this;
        }

        public Builder withX5c(String cert) {
            this.x5c.add(cert);
            return this;
        }

        public Builder withX5t(String x5t) {
            this.x5t = x5t;
            return this;
        }

        public Builder withX5tS256(String x5tS256) {
            this.x5tS256 = x5tS256;
            return this;
        }

        public Builder withKeySize(int keySizeBytes) {
            this.keySize = keySizeBytes;
            return this;
        }

        public Builder withEcCurve(EcCurve curve) {
            this.ecCurve = curve;
            return this;
        }

        public JsonWebKey generate(KeyType keyType) {

            if(algorithm != null && algorithm.type() != keyType) {
                throw new IllegalStateException("Algorithm " + algorithm + " does not match key type " + keyType);
            }

            Value value = switch(keyType) {
                case OCTET_SEQUENCE -> {
                    int size = switch(algorithm) {
                        case HS256 -> 32;
                        case HS384 -> 48;
                        case HS512 -> 64;
                        case A128KW -> 16;
                        case A192KW -> 24;
                        case A256KW -> 32;
                        case A128GCMKW -> 16;
                        case A192GCMKW -> 24;
                        case A256GCMKW -> 32;
                        case PBES2_HS256_A128KW -> 16;
                        case PBES2_HS384_A192KW -> 24;
                        case PBES2_HS512_A256KW -> 32;
                        case DIRECT -> keySize > 0 ? keySize : 32;
                        default -> throw new IllegalStateException("Unsupported algorithm: " + algorithm);
                    };

                    if(size == 0) {
                        throw new IllegalStateException("Key size must be specified for algorithm " + algorithm);
                    }

                    byte[] seq = new byte[size];
                    new SecureRandom().nextBytes(seq);
                    yield new KeyValues.OctetSequence(seq);
                }
                case RSA -> {

                    KeyPairGenerator pair;
                    try {
                        pair = KeyPairGenerator.getInstance("RSA");
                    } catch(GeneralSecurityException e) {
                        throw new RuntimeException("RSA error ", e);
                    }
                    pair.initialize(keySize > 0 ? keySize * 8 : 2048);
                    KeyPair kp = pair.generateKeyPair();

                    yield new KeyValues.Rsa((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());
                }
                case ELLIPTIC_CURVE -> {

                    EcCurve curve = this.ecCurve != null ? this.ecCurve : switch(algorithm) {
                        case ES256, ECDH_ES, ECDH_ES_A128KW -> EcCurve.P256;
                        case ES384, ECDH_ES_A192KW -> EcCurve.P384;
                        case ES512, ECDH_ES_A256KW -> EcCurve.P521;
                        default -> throw new IllegalStateException("Unsupported algorithm: " + algorithm);
                    };

                    KeyPair keyPair;
                    try { 
                        keyPair = curve.generateKeyPair(); 
                    } catch(GeneralSecurityException e) {
                        throw new RuntimeException("EC error ", e);
                    }

                    yield new KeyValues.Ec(curve, (ECPublicKey) keyPair.getPublic(), (ECPrivateKey) keyPair.getPrivate());
                }
            };

            Meta meta = new Meta(use, EnumSet.copyOf(operations), algorithm, keyId, x5u, List.copyOf(x5c), x5t, x5tS256);
            return new JsonWebKey(meta, value);
        }

    }


}
