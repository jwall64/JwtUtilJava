import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.wallentines.jwt.Algorithm;
import org.wallentines.jwt.JsonWebKey;
import org.wallentines.jwt.Jwt;
import org.wallentines.jwt.KeyType;
import org.wallentines.jwt.KeyVerifier;
import org.wallentines.jwt.TokenValidator;

public class TestValidator {

    @Test
    public void testPresent() {

        JsonWebKey key = JsonWebKey.builder()
            .withAlgorithm(Algorithm.HS256)
            .generate(KeyType.OCTET_SEQUENCE);

        String token = Jwt.builder()
            .withClaim("test", 42)
            .buildSigned(key, key.algorithm());

        TokenValidator validator = new TokenValidator.ExpectPresent(List.of("test"));

        Assertions.assertTrue(validator.validate(token, key, KeyVerifier.DEFAULT));

    }

}
