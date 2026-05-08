import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.wallentines.jwt.JsonWebKey;
import org.wallentines.jwt.JsonWebKey.Meta;
import org.wallentines.jwt.KeyUse;
import org.wallentines.jwt.Jwt;
import org.wallentines.jwt.Algorithm;
import org.wallentines.jwt.CryptAlgorithm;
import org.wallentines.jwt.KeySupplier;
import org.wallentines.jwt.KeyVerifier;
import org.wallentines.jwt.KeyOperation;
import org.wallentines.jwt.KeyUse;
import org.wallentines.jwt.KeyType;
import org.wallentines.jwt.impl.KeyValues;

import java.util.EnumSet;
import java.security.SecureRandom;

public class TestJwt {

    @Test
    public void hs256() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.HS256)
            .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.HS256);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void hs384() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.HS384)
            .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.HS384);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void hs512() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.HS512)
            .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.HS512);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void rs256() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.RS256)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.RS256);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void rs384() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.RS384)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.RS384);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void rs512() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.RS512)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.RS512);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void es256() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.ES256)
            .generate(KeyType.ELLIPTIC_CURVE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.ES256);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void es384() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.ES384)
            .generate(KeyType.ELLIPTIC_CURVE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.ES384);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void es512() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.ES512)
            .generate(KeyType.ELLIPTIC_CURVE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.ES512);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }


    @Test
    public void ps256() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.PS256)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.PS256);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void ps384() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.PS384)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.PS384);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void ps512() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.SIGNING)
            .withOperation(KeyOperation.SIGN)
            .withOperation(KeyOperation.VERIFY)
            .withAlgorithm(Algorithm.PS512)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, Algorithm.PS512);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }


    @Test
    public void rsa1_5() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.ENCRYPTION)
            .withOperation(KeyOperation.WRAP_KEY)
            .withOperation(KeyOperation.UNWRAP_KEY)
            .withAlgorithm(Algorithm.RSA1_5)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildEncrypted(key, Algorithm.RSA1_5, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void rsaOaep() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.ENCRYPTION)
            .withOperation(KeyOperation.WRAP_KEY)
            .withOperation(KeyOperation.UNWRAP_KEY)
            .withAlgorithm(Algorithm.RSA_OAEP)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildEncrypted(key, Algorithm.RSA_OAEP, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void rsaOaep256() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.ENCRYPTION)
            .withOperation(KeyOperation.WRAP_KEY)
            .withOperation(KeyOperation.UNWRAP_KEY)
            .withAlgorithm(Algorithm.RSA_OAEP_256)
            .generate(KeyType.RSA);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildEncrypted(key, Algorithm.RSA_OAEP_256, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void direct() {
        
        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.ENCRYPTION)
            .withOperation(KeyOperation.ENCRYPT)
            .withOperation(KeyOperation.DECRYPT)
            .withAlgorithm(Algorithm.DIRECT)
            .withKeySize(32)
            .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildEncrypted(key, Algorithm.DIRECT, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void ecdhEs() {

        JsonWebKey key = JsonWebKey.builder()
            .withUse(KeyUse.ENCRYPTION)
            .withOperation(KeyOperation.DERIVE_KEY)
            .withAlgorithm(Algorithm.ECDH_ES)
            .generate(KeyType.ELLIPTIC_CURVE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildEncrypted(key, Algorithm.ECDH_ES, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void ecdhEsA128KW() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.DERIVE_KEY)
                .withAlgorithm(Algorithm.ECDH_ES_A128KW)
                .generate(KeyType.ELLIPTIC_CURVE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.ECDH_ES_A128KW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void ecdhEsA192KW() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.DERIVE_KEY)
                .withAlgorithm(Algorithm.ECDH_ES_A192KW)
                .generate(KeyType.ELLIPTIC_CURVE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.ECDH_ES_A192KW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void ecdhEsA256KW() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.DERIVE_KEY)
                .withAlgorithm(Algorithm.ECDH_ES_A256KW)
                .generate(KeyType.ELLIPTIC_CURVE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.ECDH_ES_A256KW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void a128gwmkw() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.WRAP_KEY)
                .withOperation(KeyOperation.UNWRAP_KEY)
                .withAlgorithm(Algorithm.A128GCMKW)
                .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.A128GCMKW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void a192gwmkw() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.WRAP_KEY)
                .withOperation(KeyOperation.UNWRAP_KEY)
                .withAlgorithm(Algorithm.A192GCMKW)
                .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.A192GCMKW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void a256gwmkw() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.WRAP_KEY)
                .withOperation(KeyOperation.UNWRAP_KEY)
                .withAlgorithm(Algorithm.A256GCMKW)
                .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.A256GCMKW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void pbes2Hs256A128kw() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.DERIVE_KEY)
                .withAlgorithm(Algorithm.PBES2_HS256_A128KW)
                .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.PBES2_HS256_A128KW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void pbes2Hs384A192kw() {

        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.DERIVE_KEY)
                .withAlgorithm(Algorithm.PBES2_HS384_A192KW)
                .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.PBES2_HS384_A192KW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }

    @Test
    public void pbes2Hs512A256kw() {
        
        JsonWebKey key = JsonWebKey.builder()
                .withUse(KeyUse.ENCRYPTION)
                .withOperation(KeyOperation.DERIVE_KEY)
                .withAlgorithm(Algorithm.PBES2_HS512_A256KW)
                .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
                .withClaim("test", 42)
                .buildEncrypted(key, Algorithm.PBES2_HS512_A256KW, CryptAlgorithm.A256GCM);

        Jwt parsed = Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT);
        Assertions.assertEquals(42, parsed.payload().getInt("test"));
    }
}
