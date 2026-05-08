package org.wallentines.jwt;

import org.wallentines.mdcfg.serializer.ObjectSerializer;
import org.wallentines.mdcfg.serializer.Serializer;

public record KeyVerifier(boolean requireAlgorithm, boolean requireUse, boolean requireOps) {

    public static KeyVerifier DEFAULT = new KeyVerifier(true, false, false);

    public boolean verify(JsonWebKey key, Algorithm alg, KeyUse use, KeyOperation op) {

        return key.mayUseAlg(alg, !requireAlgorithm) && key.mayUseFor(use, !requireUse) && key.mayUseOp(op, !requireOps);
    }

    public static Serializer<KeyVerifier> SERIALIZER = ObjectSerializer.create(
        Serializer.BOOLEAN.entry("require_algorithm", KeyVerifier::requireAlgorithm).orElse(true),
        Serializer.BOOLEAN.entry("require_use", KeyVerifier::requireUse).orElse(false),
        Serializer.BOOLEAN.entry("require_ops", KeyVerifier::requireOps).orElse(false),
        KeyVerifier::new
    );

}
