package org.wallentines.jwt.impl;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.jetbrains.annotations.Nullable;
import org.wallentines.jwt.EcCurve;
import org.wallentines.jwt.JsonWebKey;
import org.wallentines.jwt.KeyType;
import org.wallentines.mdcfg.serializer.ObjectSerializer;
import org.wallentines.mdcfg.serializer.Serializer;

public class KeyValues {
 
    public record OctetSequence(byte[] data) implements JsonWebKey.Value {

        public KeyType type() {
            return KeyType.OCTET_SEQUENCE;
        }

        public static final Serializer<OctetSequence> SERIALIZER = ObjectSerializer.create(
            ExtraSerializers.BYTE_ARRAY.entry("k", OctetSequence::data),
            OctetSequence::new
        );

    }

    public record Rsa(RSAPublicKey pub, @Nullable RSAPrivateKey key) implements JsonWebKey.Value {

        public Rsa(BigInteger n, BigInteger e, @Nullable BigInteger d, @Nullable BigInteger p, 
                    @Nullable BigInteger q, @Nullable BigInteger dp, @Nullable BigInteger dq, 
                    @Nullable BigInteger qi) throws GeneralSecurityException {

            RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(n, e);
            RSAPrivateKeySpec privSpec = null;
            if(d != null) {
                privSpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
            }

            RSAPublicKey pubKey = (RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(pubSpec);
            RSAPrivateKey privKey = null;
            if(privSpec != null) {
                privKey = (RSAPrivateKey) java.security.KeyFactory.getInstance("RSA").generatePrivate(privSpec);
            }

            this(pubKey, privKey);
        }

        public KeyType type() {
            return KeyType.RSA;
        }

        public BigInteger n() {
            return pub.getModulus();
        }
        public BigInteger e() {
            return pub.getPublicExponent();
        }
        public BigInteger d() {
            if(key == null) return null;
            return key.getPrivateExponent();
        }

        public BigInteger p() {
            if(key == null) return null;
            return ((RSAPrivateCrtKeySpec) key.getParams()).getPrimeP();
        }

        public BigInteger q() {
            if(key == null) return null;
            return ((RSAPrivateCrtKeySpec) key.getParams()).getPrimeQ();
        }

        public BigInteger dp() {
            if(key == null) return null;
            return ((RSAPrivateCrtKeySpec) key.getParams()).getPrimeExponentP();
        }

        public BigInteger dq() {
            if(key == null) return null;
            return ((RSAPrivateCrtKeySpec) key.getParams()).getPrimeExponentQ();
        }

        public BigInteger qi() {
            if(key == null) return null;
            return ((RSAPrivateCrtKeySpec) key.getParams()).getCrtCoefficient();
        }


        public static final Serializer<Rsa> SERIALIZER = ObjectSerializer.create(
            ExtraSerializers.BIG_INTEGER.entry("n", Rsa::n),
            ExtraSerializers.BIG_INTEGER.entry("e", Rsa::e),
            ExtraSerializers.BIG_INTEGER.entry("d", Rsa::d).optional(),
            ExtraSerializers.BIG_INTEGER.entry("p", Rsa::p).optional(),
            ExtraSerializers.BIG_INTEGER.entry("q", Rsa::q).optional(),
            ExtraSerializers.BIG_INTEGER.entry("dp", Rsa::dp).optional(),
            ExtraSerializers.BIG_INTEGER.entry("dq", Rsa::dq).optional(),
            ExtraSerializers.BIG_INTEGER.entry("qi", Rsa::qi).optional(),
            (n, e, d, p, q, dp, dq, qi) -> {
                try {
                    return new Rsa(n, e, d, p, q, dp, dq, qi);
                } catch(GeneralSecurityException ex) {
                    throw new RuntimeException("Failed to create RSA key", ex);
                }
            }
        );

        public Rsa withoutPrivate() {
            return new Rsa(pub, null);
        }

    }

    public record Ec(EcCurve curve, ECPublicKey pub, @Nullable ECPrivateKey key) implements JsonWebKey.Value {
        
        public Ec(EcCurve curve, BigInteger x, BigInteger y, @Nullable BigInteger d) throws GeneralSecurityException {
            this(curve, curve.publicKey(x, y), d == null ? null : curve.privateKey(d));
        }

        @Override
        public KeyType type() {
            return KeyType.ELLIPTIC_CURVE;
        }

        public BigInteger x() {
            return curve.x(pub);
        }
        public BigInteger y() {
            return curve.y(pub);
        }

        public BigInteger d() {
            if(key == null) return null;
            return curve.d(key);
        }

        public static final Serializer<Ec> SERIALIZER = ObjectSerializer.create(
            EcCurve.SERIALIZER.entry("crv", Ec::curve),
            ExtraSerializers.BIG_INTEGER.entry("x", Ec::x),
            ExtraSerializers.BIG_INTEGER.entry("y", Ec::y),
            ExtraSerializers.BIG_INTEGER.entry("d", Ec::d).optional(),
            (curve, x, y, d) -> {
                try {
                    return new Ec(curve, x, y, d);
                } catch(GeneralSecurityException e) {
                    throw new RuntimeException("Failed to create EC key", e);
                }
            }
        );

        public Ec withoutPrivate() {
            return new Ec(curve, pub, null);
        }

    }

    public static Serializer<JsonWebKey.Value> SERIALIZER = KeyType.SERIALIZER.fieldOf("kty").dispatch(
        kty -> {
            if(kty == KeyType.OCTET_SEQUENCE) return KeyValues.OctetSequence.SERIALIZER;
            if(kty == KeyType.RSA) return KeyValues.Rsa.SERIALIZER;
            if(kty == KeyType.ELLIPTIC_CURVE) return KeyValues.Ec.SERIALIZER;
            return null;
        }, 
        value -> {
            return value.type();
        });

}
