package org.wallentines.jwt;

import org.jetbrains.annotations.Nullable;
import org.wallentines.mdcfg.ConfigSection;

public interface KeySupplier {

    @Nullable
    JsonWebKey getKey(ConfigSection header);

    default KeySupplier or(KeySupplier other) {
        return header -> {
            JsonWebKey key = getKey(header);
            if (key != null) return key;
            return other.getKey(header);
        };
    }

}
