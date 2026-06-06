package org.wallentines.jwt;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.wallentines.jwt.impl.ExtraSerializers;
import org.wallentines.mdcfg.ConfigObject;
import org.wallentines.mdcfg.registry.Registry;
import org.wallentines.mdcfg.serializer.ObjectSerializer;
import org.wallentines.mdcfg.serializer.Serializer;

public interface TokenValidator {

    public static final Registry<String, Serializer<? extends TokenValidator>> REGISTRY = Registry.createStringRegistry(); 

    public static final Serializer<TokenValidator> SERIALIZER = REGISTRY.byIdSerializer().fieldOf("type").dispatch(
        ser -> ser,
        val -> val.serializer()
    );

    static <T extends TokenValidator> Serializer<T> register(String key, Serializer<T> value) {
        REGISTRY.register(key, value);
        return value;
    }

    boolean validate(Jwt token);

    Serializer<? extends TokenValidator> serializer();

    default boolean validate(String token, KeySupplier key) {
        try {
            return validate(Jwt.parseAndVerify(token, key, KeyVerifier.DEFAULT));
        } catch (Exception ex) {
            return false;
        }
    }

    default boolean validate(String token, KeySupplier key, KeyVerifier verifier) {
        try {
            return validate(Jwt.parseAndVerify(token, key, verifier));
        } catch (Exception ex) {
            return false;
        }
    }


    record ExpectClaims(Map<String, ConfigObject> claims) implements TokenValidator {

        @Override
        public boolean validate(Jwt token) {
            for (var entry : claims.entrySet()) {
                var claim = token.payload().get(entry.getKey());
                if (claim == null || !claim.equals(entry.getValue())) {
                    return false;
                }
            }
            return true;
        }

        public Serializer<ExpectClaims> serializer() {
            return SERIALIZER;
        }

        public static final Serializer<ExpectClaims> SERIALIZER = register("expect_claims", ConfigObject.SERIALIZER.mapOf().fieldOf("claims")
                .flatMap(ExpectClaims::claims, ExpectClaims::new));
    }

    record ExpectPattern(Map<String, Pattern> patterns) implements TokenValidator {

        @Override
        public boolean validate(Jwt token) {
            for (var entry : patterns.entrySet()) {
                var claim = token.payload().get(entry.getKey());
                if(!claim.isString() || !entry.getValue().matcher(claim.asString()).matches()) {
                    return false;
                }
            }
            return true;
        }

        public Serializer<ExpectPattern> serializer() {
            return SERIALIZER;
        }

        public static final Serializer<ExpectPattern> SERIALIZER = register("expect_pattern", ExtraSerializers.PATTERN.mapOf().fieldOf("claims")
                .flatMap(ExpectPattern::patterns, ExpectPattern::new));
    }

    record ExpectPresent(List<String> claimKeys) implements TokenValidator {
        @Override
        public boolean validate(Jwt token) {
            for (var key : claimKeys) {
                if (!token.payload().has(key)) {
                    return false;
                }
            }
            return true;
        }

        public Serializer<ExpectPresent> serializer() {
            return SERIALIZER;
        }

        public static final Serializer<ExpectPresent> SERIALIZER = register("expect_present", Serializer.STRING.listOf().mapToList().fieldOf("claims")
                .flatMap(ExpectPresent::claimKeys, ExpectPresent::new));
    }


    class SingleUse implements TokenValidator {
        private final Map<String, Long> usedTokens;

        private final String claimId;
        private final long expirationMs;

        public SingleUse() {
            this("jti", 60 * 60 * 1000); // Default to 1 hour expiration
        }

        public SingleUse(String claimId, long expirationMs) {
            this.usedTokens = new HashMap<>();
            this.claimId = claimId;
            this.expirationMs = expirationMs;
        }

        @Override
        public boolean validate(Jwt token) {
            var jti = token.payload().get(claimId);
            if (jti == null || !jti.isString()) {
                return false;
            }
            var id = jti.asString();
            synchronized (usedTokens) {

                if(expirationMs > 0) usedTokens.entrySet().removeIf(entry -> entry.getValue() < System.currentTimeMillis() - (expirationMs));
                if (usedTokens.containsKey(id)) {
                    return false;
                }
                usedTokens.put(id, System.currentTimeMillis());
                return true;
            }
        }

        @Override
        public Serializer<SingleUse> serializer() {
            return SERIALIZER;
        }

        public static final Serializer<SingleUse> SERIALIZER = register("single_use", ObjectSerializer.create(
            Serializer.STRING.<SingleUse>entry("claimId", su -> su.claimId).orElse("jti"),
            Serializer.LONG.<SingleUse>entry("expirationMs", su -> su.expirationMs).orElse(60 * 60 * 1000L),
            SingleUse::new
        ));
    }

    record AllOf(List<TokenValidator> validators) implements TokenValidator {

        @Override
        public boolean validate(Jwt token) {
            for (var validator : validators) {
                if (!validator.validate(token)) {
                    return false;
                }
            }
            return true;
        }

        public Serializer<AllOf> serializer() {
            return SERIALIZER;
        }

        public static final Serializer<AllOf> SERIALIZER = register("all_of", ObjectSerializer.create(
            TokenValidator.SERIALIZER.listOf().mapToList().<AllOf>entry("validators", v -> v.validators),
            AllOf::new
        ));
    }

    record AnyOf(List<TokenValidator> validators) implements TokenValidator {

        @Override
        public boolean validate(Jwt token) {
            for (var validator : validators) {
                if (validator.validate(token)) {
                    return true;
                }
            }
            return false;
        }

        public Serializer<AnyOf> serializer() {
            return SERIALIZER;
        }

        public static final Serializer<AnyOf> SERIALIZER = register("any_of", ObjectSerializer.create(
            TokenValidator.SERIALIZER.listOf().mapToList().<AnyOf>entry("validators", v -> v.validators),
            AnyOf::new
        ));
    }

    record Not(TokenValidator validator) implements TokenValidator {
        @Override
        public boolean validate(Jwt token) {
            return !validator.validate(token);
        }

        public Serializer<Not> serializer() {
            return SERIALIZER;
        }

        public static final Serializer<Not> SERIALIZER = register("not", ObjectSerializer.create(
            TokenValidator.SERIALIZER.<Not>entry("validator", v -> v.validator),
            Not::new
        ));
    }

}
