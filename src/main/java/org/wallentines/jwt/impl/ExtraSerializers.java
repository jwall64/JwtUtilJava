package org.wallentines.jwt.impl;

import java.math.BigInteger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.wallentines.mdcfg.serializer.SerializeResult;
import org.wallentines.mdcfg.serializer.Serializer;

public class ExtraSerializers {

    public static Serializer<byte[]> BYTE_ARRAY = Serializer.STRING.map(bytes -> {
        return SerializeResult.success(Base64Util.encode(bytes));
    }, str -> {
        try {
            return SerializeResult.success(Base64Util.decode(str));
        } catch(IllegalArgumentException e) {
            return SerializeResult.failure("Invalid base64 encoding");
        }
    });

    public static Serializer<BigInteger> BIG_INTEGER = BYTE_ARRAY.map(bigInt -> {
        byte[] bytes = bigInt.toByteArray();
        return SerializeResult.success(bytes);
    }, bytes -> {
        return SerializeResult.success(new BigInteger(bytes));
    });

    public static Serializer<Pattern> PATTERN = Serializer.STRING.map(
        pattern -> SerializeResult.success(pattern.pattern()),
        str -> {
            try {
                return SerializeResult.success(Pattern.compile(str));
            } catch (PatternSyntaxException e) {
                return SerializeResult.failure("Invalid regex pattern: " + e.getMessage());
            }
        });

}
