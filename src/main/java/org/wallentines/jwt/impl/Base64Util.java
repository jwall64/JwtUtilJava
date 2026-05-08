package org.wallentines.jwt.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.wallentines.mdcfg.ConfigSection;
import org.wallentines.mdcfg.codec.JSONCodec;
import org.wallentines.mdcfg.serializer.ConfigContext;

public class Base64Util {

    public static String encode(byte[] data) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] decode(String data) {
        return java.util.Base64.getUrlDecoder().decode(data);
    }

    public static String encode(ConfigSection section) {
        String json = JSONCodec.minified().encodeToString(ConfigContext.INSTANCE, section);
        return encode(json.getBytes());
    }

    public static ConfigSection decodeToSection(String data) {
        try(ByteArrayInputStream bis = new ByteArrayInputStream(Base64Util.decode(data))) {
            return JSONCodec
                .minified()
                .decode(ConfigContext.INSTANCE, bis, StandardCharsets.UTF_8)
                .asSection();
        } catch(IOException e) {
            throw new RuntimeException("Failed to decode Base64 JSON", e);
        }
    }
}
