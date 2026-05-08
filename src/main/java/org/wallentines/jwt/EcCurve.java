package org.wallentines.jwt;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import org.wallentines.mdcfg.serializer.Serializer;

public enum EcCurve {

    P256("P-256"),
    P384("P-384"),
    P521("P-521");

    private String id;

    EcCurve(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }


    public BigInteger x(ECPublicKey pub) {
        return pub.getW().getAffineX();
    }
    public BigInteger y(ECPublicKey pub) {
        return pub.getW().getAffineY();
    }
    public BigInteger d(ECPrivateKey key) {
        return key.getS();
    }

    public ECParameterSpec params() throws GeneralSecurityException {
        String curveName = switch(this) {
            case P256 -> "secp256r1";
            case P384 -> "secp384r1";
            case P521 -> "secp521r1";
        };

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new java.security.spec.ECGenParameterSpec(curveName));
        return params.getParameterSpec(ECParameterSpec.class);
    }

    public ECPublicKey publicKey(BigInteger x, BigInteger y) throws GeneralSecurityException {
        try {
            ECPoint point = new java.security.spec.ECPoint(x, y);
            ECParameterSpec params = params();
            ECPublicKeySpec pubSpec = new java.security.spec.ECPublicKeySpec(point, params);
            return (ECPublicKey) java.security.KeyFactory.getInstance("EC").generatePublic(pubSpec);
        } catch(Exception e) {
            throw new RuntimeException("Failed to generate public key", e);
        }
    }

    public ECPrivateKey privateKey(BigInteger d) {
        try {
            ECParameterSpec params = params();
            ECPrivateKeySpec privSpec = new java.security.spec.ECPrivateKeySpec(d, params);
            return (ECPrivateKey) java.security.KeyFactory.getInstance("EC").generatePrivate(privSpec);
        } catch(Exception e) {
            throw new RuntimeException("Failed to generate private key", e);
        }
    }

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("EC");
        keyGen.initialize(params());
        return keyGen.generateKeyPair();
    }

    public static EcCurve byId(String name) {
        for (EcCurve curve : values()) {
            if (curve.id().equals(name)) {
                return curve;
            }
        }
        return null;
    }

    public static Serializer<EcCurve> SERIALIZER = Serializer.STRING.flatMap(EcCurve::id, EcCurve::byId);

}
