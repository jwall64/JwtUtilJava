package org.wallentines.jwt;


import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import org.wallentines.jwt.impl.Base64Util;
import org.wallentines.jwt.impl.CekUtil;
import org.wallentines.jwt.impl.CryptUtil;
import org.wallentines.jwt.impl.SignatureUtil;
import org.wallentines.jwt.impl.CekUtil.GeneratedCek;
import org.wallentines.jwt.impl.CryptUtil.CryptOutput;
import org.wallentines.mdcfg.ConfigObject;
import org.wallentines.mdcfg.ConfigSection;
import org.wallentines.mdcfg.serializer.Serializer;

public interface Jwt {


    ConfigSection header();

    ConfigSection payload();
 

    public record Unprotected(ConfigSection header, ConfigSection payload) implements Jwt {}

    public record Signed(ConfigSection header, ConfigSection payload, String signature, boolean verified) implements Jwt {}

    public record Encrypted(ConfigSection header, ConfigSection payload, byte[] encryptedKey, byte[] iv, byte[] ciphertext, byte[] tag) implements Jwt {}


    public static String CLAIM_ALGORITHM = "alg";
    public static String CLAIM_ENCRYPTION_ALGORITHM = "enc";
    public static String CLAIM_TYPE = "typ";
    public static String CLAIM_CONTENT_TYPE = "cty";
    public static String CLAIM_KEY_ID = "kid";
    public static String CLAIM_ISSUER = "iss";
    public static String CLAIM_SUBJECT = "sub";
    public static String CLAIM_AUDIENCE = "aud";
    public static String CLAIM_EXPIRATION = "exp";
    public static String CLAIM_NOT_BEFORE = "nbf";
    public static String CLAIM_ISSUED_AT = "iat";
    public static String CLAIM_JWT_ID = "jti";


    public static ConfigSection readHeader(String jwt) {
        String[] parts = jwt.split("\\.");
        if(parts.length < 1) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        return Base64Util.decodeToSection(parts[0]);
    }

    public static Jwt parseAndVerify(String token, KeySupplier supplier, KeyVerifier verifier) {
        return parseAndVerify(token, supplier, verifier, false, false, false);
    }

    public static Jwt parseAndVerify(String token, KeySupplier supplier, KeyVerifier verifier, boolean allowUnprotected, boolean allowExpired, boolean allowEarly) {
        Jwt jwt = parseOnly(token, supplier, verifier);
        if(jwt instanceof Unprotected) {
            if(!allowUnprotected) {
                throw new IllegalArgumentException("Unprotected JWTs are not allowed");
            }
        } else if(jwt instanceof Signed signed) {
            if(!signed.verified()) {
                throw new IllegalArgumentException("Invalid signature in signed JWT");
            }
        } 

        if(!allowExpired && jwt.payload().has(CLAIM_EXPIRATION)) {
            Number exp = jwt.payload().getNumber(CLAIM_EXPIRATION);
            if(System.currentTimeMillis() / 1000 >= exp.longValue()) {
                throw new IllegalStateException("Token is expired");
            }
        }
        if(!allowEarly && jwt.payload().has(CLAIM_NOT_BEFORE)) {
            Number nbf = jwt.payload().getNumber(CLAIM_NOT_BEFORE);
            if(System.currentTimeMillis() / 1000 < nbf.longValue()) {
                throw new IllegalStateException("Token is early");
            }
        }

        return jwt;
    }

    public static Jwt parseOnly(String token, KeySupplier supplier, KeyVerifier verifier) {

        String[] parts = token.split("\\.");
        if(parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT format");
        }

        ConfigSection header = Base64Util.decodeToSection(parts[0]);
        String alg = header.getString(CLAIM_ALGORITHM);
        Algorithm algorithm = Algorithm.byId(alg);
        if(algorithm == null) {
            throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        }

        String typ = header.getOrDefault(CLAIM_TYPE, (String) null);
        if(!"jwt".equals(typ) && !"JWT".equals(typ)) {
            throw new IllegalArgumentException("Unsupported content type: " + typ);
        }

        if(parts.length == 3) {

            ConfigSection payload = Base64Util.decodeToSection(parts[1]);
            if(algorithm == Algorithm.NONE) {
                return new Unprotected(header, payload);
            }

            JsonWebKey key = supplier.getKey(header);
            if(!verifier.verify(key, algorithm, KeyUse.SIGNING, KeyOperation.VERIFY)) {
                throw new IllegalArgumentException("Key is not valid for verifying the signature with the given algorithm");
            }

            byte[] sig = Base64Util.decode(parts[2]);
            boolean valid = false;
            try {
                valid = SignatureUtil.verify((parts[0] + "." + parts[1]).getBytes(), sig, key, algorithm);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Failed to verify JWT signature", e);
            }
            return new Signed(header, payload, parts[2], valid);

        } else if(parts.length == 5) {

            byte[] encryptedKey = Base64Util.decode(parts[1]);
            byte[] iv = Base64Util.decode(parts[2]);
            byte[] ciphertext = Base64Util.decode(parts[3]);
            byte[] tag = Base64Util.decode(parts[4]);

            JsonWebKey key = supplier.getKey(header);
            CryptAlgorithm enc = CryptAlgorithm.byId(header.getString(CLAIM_ENCRYPTION_ALGORITHM));

            if(enc == null) {
                throw new IllegalArgumentException("Unsupported encryption algorithm: " + header.getString("enc"));
            }

            byte[] cek;
            try{
                cek = CekUtil.getCek(encryptedKey, header, key, algorithm, enc, verifier);
            } catch(GeneralSecurityException e) {
                throw new RuntimeException("Failed to decrypt CEK for JWT decryption", e);
            }

            byte[] payloadBytes;
            try {
                payloadBytes = CryptUtil.decrypt(ciphertext, iv, parts[0].getBytes(), tag, cek, enc);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Failed to decrypt JWT payload", e);
            }

            ConfigSection payload = Base64Util.decodeToSection(new String(payloadBytes));
            return new Encrypted(header, payload, encryptedKey, iv, ciphertext, tag);

        } else {
            throw new IllegalArgumentException("Invalid JWT format");
        }

    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private final ConfigSection header = new ConfigSection();
        private final ConfigSection payload = new ConfigSection();
        private boolean writeKeyId;
        private boolean skipIssuedAt;

        public Builder withHeaderClaim(String name, String value) {
            header.set(name, value);
            return this;
        }

        public Builder withHeaderClaim(String name, boolean value) {
            header.set(name, value);
            return this;
        }

        public Builder withHeaderClaim(String name, Number value) {
            header.set(name, value);
            return this;
        }

        public Builder withHeaderClaim(String name, ConfigObject value) {
            header.set(name, value);
            return this;
        }

        public <T> Builder withHeaderClaim(String name, T value, Serializer<T> serializer) {
            header.set(name, value, serializer);
            return this;
        }

        public Builder withHeaderClaims(ConfigSection claims) {
            header.fillOverwrite(claims);
            return this;
        }

        public Builder withClaim(String name, String value) {
            payload.set(name, value);
            return this;
        }

        public Builder withClaim(String name, boolean value) {
            payload.set(name, value);
            return this;
        }

        public Builder withClaim(String name, Number value) {
            payload.set(name, value);
            return this;
        }

        public Builder withClaim(String name, ConfigObject value) {
            payload.set(name, value);
            return this;
        }

        public <T> Builder withClaim(String name, T value, Serializer<T> serializer) {
            payload.set(name, value, serializer);
            return this;
        }

        public Builder withClaims(ConfigSection claims) {
            payload.fillOverwrite(claims);
            return this;
        }

        public Builder withContentType(String cty) {
            return withHeaderClaim(CLAIM_CONTENT_TYPE, cty);
        }

        public Builder withIssuer(String issuer) {
            return withClaim(CLAIM_ISSUER, issuer);
        }

        public Builder withSubject(String subject) {
            return withClaim(CLAIM_SUBJECT, subject);
        }

        public Builder withAudience(String audience) {
            return withClaim(CLAIM_AUDIENCE, audience);
        }

        public Builder expiresIn(long seconds) {
            return withClaim(CLAIM_EXPIRATION, (System.currentTimeMillis() / 1000) + seconds);
        }

        public Builder expiresAt(long timestamp) {
            return withClaim(CLAIM_EXPIRATION, timestamp);
        }

        public Builder validIn(long seconds) {
            return withClaim(CLAIM_NOT_BEFORE, (System.currentTimeMillis() / 1000) + seconds);
        }

        public Builder validAt(long timestamp) {
            return withClaim(CLAIM_NOT_BEFORE, timestamp);
        }

        public Builder withJwtId(String id) {
            return withClaim(CLAIM_JWT_ID, id);
        }

        public Builder writeKeyId(boolean writeKeyId) {
            this.writeKeyId = writeKeyId;
            return this;
        }

        public Builder skipIssuedAt(boolean skipIssuedAt) {
            this.skipIssuedAt = skipIssuedAt;
            return this;
        }

        public String buildUnprotected() {

            ConfigSection header = this.header.copy();
            header.set(CLAIM_ALGORITHM, "none");
            header.set(CLAIM_TYPE, "jwt");
            if(!skipIssuedAt) header.set(CLAIM_ISSUED_AT, System.currentTimeMillis());

            return "%s.%s.".formatted(Base64Util.encode(header), Base64Util.encode(payload));
        }

        public String buildSigned(JsonWebKey key, Algorithm algorithm) {
            return buildSigned(key, algorithm, KeyVerifier.DEFAULT);
        }

        public String buildSigned(JsonWebKey key, Algorithm algorithm, KeyVerifier verifier) { 

            if(!verifier.verify(key, algorithm, KeyUse.SIGNING, KeyOperation.SIGN)) {
                throw new IllegalArgumentException("Key is not valid for signing with the given algorithm");
            }
            if(algorithm.use() != KeyUse.SIGNING) {
                throw new IllegalArgumentException("Algorithm is not a signature algorithm");
            }

            ConfigSection header = this.header.copy();
            header.set(CLAIM_ALGORITHM, algorithm.name());
            header.set(CLAIM_TYPE, "jwt");
            if(!skipIssuedAt) header.set(CLAIM_ISSUED_AT, System.currentTimeMillis());
            if(writeKeyId) {
                if(key.keyId() == null) {
                    throw new IllegalArgumentException("Key ID is required but not present in the key");
                }
                header.set(CLAIM_KEY_ID, key.keyId());
            }

            String headerString = Base64Util.encode(header);
            String payloadString = Base64Util.encode(payload);
            String signatureString;

            byte[] data = (headerString + "." + payloadString).getBytes();
            try {
                byte[] signature = SignatureUtil.sign(data, key, algorithm);
                signatureString = Base64Util.encode(signature);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Failed to sign JWT", e);
            }

            return "%s.%s.%s".formatted(headerString, payloadString, signatureString);
        }

        public String buildEncrypted(JsonWebKey key, Algorithm algorithm, CryptAlgorithm cryptAlgorithm) {
            return buildEncrypted(key, algorithm, cryptAlgorithm, KeyVerifier.DEFAULT);
        }

        public String buildEncrypted(JsonWebKey key, Algorithm algorithm, CryptAlgorithm cryptAlgorithm, KeyVerifier verifier) {
            
            if(algorithm.use() != KeyUse.ENCRYPTION) {
                throw new IllegalArgumentException("Algorithm is not an encryption algorithm");
            }

            ConfigSection header = this.header.copy();
            header.set(CLAIM_ALGORITHM, algorithm.id());
            header.set(CLAIM_ENCRYPTION_ALGORITHM, cryptAlgorithm.id());
            header.set(CLAIM_TYPE, "jwt");
            if(!skipIssuedAt) header.set(CLAIM_ISSUED_AT, System.currentTimeMillis());
            if(writeKeyId) {
                if(key.keyId() == null) {
                    throw new IllegalArgumentException("Key ID is required but not present in the key");
                }
                header.set(CLAIM_KEY_ID, key.keyId());
            }

            GeneratedCek cek;
            try {
                cek = CekUtil.generateCek(header, key, algorithm, cryptAlgorithm, verifier);
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate CEK for JWT encryption", e);
            }

            String headerString = Base64Util.encode(header);
            String encryptedKeyString = cek.encryptedCek() == null ? "" : Base64Util.encode(cek.encryptedCek());
            
            String payloadString = Base64Util.encode(payload);

            byte[] iv = new byte[cryptAlgorithm.ivLength()];
            new SecureRandom().nextBytes(iv);
            String ivString = Base64Util.encode(iv);

            byte[] aad = headerString.getBytes();
            CryptOutput crypt;
            try {
                crypt = CryptUtil.encrypt(payloadString.getBytes(), iv, aad, cek.cek(), cryptAlgorithm);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Failed to encrypt JWT payload", e);
            }

            return "%s.%s.%s.%s.%s".formatted(
                headerString,
                encryptedKeyString,
                ivString,
                Base64Util.encode(crypt.ciphertext()),
                Base64Util.encode(crypt.tag())
            );

        }

    }

}
