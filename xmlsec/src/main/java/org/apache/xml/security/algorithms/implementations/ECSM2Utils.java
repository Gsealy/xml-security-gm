package org.apache.xml.security.algorithms.implementations;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public final class ECSM2Utils {

    private ECSM2Utils() {
        // complete
    }

    /**
     * Converts an ASN.1 ECDSA value to a XML Signature ECDSA Value.
     * <p></p>
     * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r, s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param asn1Bytes
     * @return the decode bytes
     * @throws IOException
     */
    public static byte[] convertASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {

        if (asn1Bytes.length < 8 || asn1Bytes[0] != 48) {
            throw new IOException("Invalid ASN.1 format of ECSM2 signature");
        }
        int offset;
        if (asn1Bytes[1] > 0) {
            offset = 2;
        } else if (asn1Bytes[1] == (byte) 0x81) {
            offset = 3;
        } else {
            throw new IOException("Invalid ASN.1 format of ECSM2 signature");
        }

        byte rLength = asn1Bytes[offset + 1];
        int i;

        for (i = rLength; i > 0 && asn1Bytes[offset + 2 + rLength - i] == 0; i--); //NOPMD

        byte sLength = asn1Bytes[offset + 2 + rLength + 1];
        int j;

        for (j = sLength; j > 0 && asn1Bytes[offset + 2 + rLength + 2 + sLength - j] == 0; j--); //NOPMD

        int rawLen = Math.max(i, j);

        if ((asn1Bytes[offset - 1] & 0xff) != asn1Bytes.length - offset
                || (asn1Bytes[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || asn1Bytes[offset] != 2
                || asn1Bytes[offset + 2 + rLength] != 2) {
            throw new IOException("Invalid ASN.1 format of ECSM2 signature");
        }
        byte xmldsigBytes[] = new byte[2 * rawLen];

        System.arraycopy(asn1Bytes, offset + 2 + rLength - i, xmldsigBytes, rawLen - i, i);
        System.arraycopy(asn1Bytes, offset + 2 + rLength + 2 + sLength - j, xmldsigBytes,
                2 * rawLen - j, j);

        return xmldsigBytes;
    }

    /**
     * Converts a XML Signature ECSM2 Value to an ASN.1 SM2 value.
     * <p></p>
     * The JAVA JCE ECSM2 Signature algorithm creates ASN.1 encoded (r, s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param xmldsigBytes
     * @return the encoded ASN.1 bytes
     * @throws IOException
     */
    public static byte[] convertXMLDSIGtoASN1(byte xmldsigBytes[]) throws IOException {

        int rawLen = xmldsigBytes.length / 2;

        int i;

        for (i = rawLen; i > 0 && xmldsigBytes[rawLen - i] == 0; i--); //NOPMD

        int j = i;

        if (xmldsigBytes[rawLen - i] < 0) {
            j += 1;
        }

        int k;

        for (k = rawLen; k > 0 && xmldsigBytes[2 * rawLen - k] == 0; k--); //NOPMD

        int l = k;

        if (xmldsigBytes[2 * rawLen - k] < 0) {
            l += 1;
        }

        int len = 2 + j + 2 + l;
        if (len > 255) {
            throw new IOException("Invalid XMLDSIG format of ECSM2 signature");
        }
        int offset;
        byte asn1Bytes[];
        if (len < 128) {
            asn1Bytes = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
            asn1Bytes = new byte[3 + 2 + j + 2 + l];
            asn1Bytes[1] = (byte) 0x81;
            offset = 2;
        }
        asn1Bytes[0] = 48;
        asn1Bytes[offset++] = (byte) len;
        asn1Bytes[offset++] = 2;
        asn1Bytes[offset++] = (byte) j;

        System.arraycopy(xmldsigBytes, rawLen - i, asn1Bytes, offset + j - i, i);

        offset += j;

        asn1Bytes[offset++] = 2;
        asn1Bytes[offset++] = (byte) l;

        System.arraycopy(xmldsigBytes, 2 * rawLen - k, asn1Bytes, offset + l - k, k);

        return asn1Bytes;
    }

    private static final List<ECCurveDefinition> ecCurveDefinitions = new ArrayList<>();

    static {

        ecCurveDefinitions.add(
                new ECCurveDefinition(
                        "secp256r1 [NIST P-256, X9.62 prime256v1]",
                        "1.2.840.10045.3.1.7",
                        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                        1)
        );
        ecCurveDefinitions.add(
        		new ECCurveDefinition(
        				"sm2p256r1 [SM P-256]",
                        "1.2.156.10197.1.301",
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a
                        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b
                        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// x
                        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",// y
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n 
        				1)
        );
    }

    public static String getOIDFromPublicKey(ECPublicKey ecPublicKey) {
        ECParameterSpec ecParameterSpec = ecPublicKey.getParams();
        BigInteger order = ecParameterSpec.getOrder();
        BigInteger affineX = ecParameterSpec.getGenerator().getAffineX();
        BigInteger affineY = ecParameterSpec.getGenerator().getAffineY();
        BigInteger a = ecParameterSpec.getCurve().getA();
        BigInteger b = ecParameterSpec.getCurve().getB();
        int h = ecParameterSpec.getCofactor();
        ECField ecField = ecParameterSpec.getCurve().getField();
        BigInteger field;
        if (ecField instanceof ECFieldFp) {
            ECFieldFp ecFieldFp = (ECFieldFp) ecField;
            field = ecFieldFp.getP();
        } else {
            ECFieldF2m ecFieldF2m = (ECFieldF2m) ecField;
            field = ecFieldF2m.getReductionPolynomial();
        }

        Iterator<ECCurveDefinition> ecCurveDefinitionIterator = ecCurveDefinitions.iterator();
        while (ecCurveDefinitionIterator.hasNext()) {
            ECCurveDefinition ecCurveDefinition = ecCurveDefinitionIterator.next();
            String oid = ecCurveDefinition.equals(field, a, b, affineX, affineY, order, h);
            if (oid != null) {
                return oid;
            }
        }
        return null;
    }

    public static ECCurveDefinition getECCurveDefinition(String oid) {
        Iterator<ECCurveDefinition> ecCurveDefinitionIterator = ecCurveDefinitions.iterator();
        while (ecCurveDefinitionIterator.hasNext()) {
            ECCurveDefinition ecCurveDefinition = ecCurveDefinitionIterator.next();
            if (ecCurveDefinition.getOid().equals(oid)) {
                return ecCurveDefinition;
            }
        }
        return null;
    }

    public static class ECCurveDefinition {

        private final String name;
        private final String oid;
        private final String field;
        private final String a;
        private final String b;
        private final String x;
        private final String y;
        private final String n;
        private final int h;

        public ECCurveDefinition(String name, String oid, String field, String a, String b, String x, String y, String n, int h) {
            this.name = name;
            this.oid = oid;
            this.field = field;
            this.a = a;
            this.b = b;
            this.x = x;
            this.y = y;
            this.n = n;
            this.h = h;
        }

        /**
         * returns the ec oid if parameter are equal to this definition
         */
        public String equals(BigInteger field, BigInteger a, BigInteger b, BigInteger x, BigInteger y, BigInteger n, int h) {
            if (this.field.equals(field.toString(16))
                    && this.a.equals(a.toString(16))
                    && this.b.equals(b.toString(16))
                    && this.x.equals(x.toString(16))
                    && this.y.equals(y.toString(16))
                    && this.n.equals(n.toString(16))
                    && this.h == h) {
                return this.oid;
            }
            return null;
        }

        public String getName() {
            return name;
        }

        public String getOid() {
            return oid;
        }

        public String getField() {
            return field;
        }

        public String getA() {
            return a;
        }

        public String getB() {
            return b;
        }

        public String getX() {
            return x;
        }

        public String getY() {
            return y;
        }

        public String getN() {
            return n;
        }

        public int getH() {
            return h;
        }
    }

    public static byte[] encodePoint(ECPoint ecPoint, EllipticCurve ellipticCurve) {
        int size = (ellipticCurve.getField().getFieldSize() + 7) / 8;
        byte affineXBytes[] = stripLeadingZeros(ecPoint.getAffineX().toByteArray());
        byte affineYBytes[] = stripLeadingZeros(ecPoint.getAffineY().toByteArray());
        byte encodedBytes[] = new byte[size * 2 + 1];
        encodedBytes[0] = 0x04; //uncompressed
        System.arraycopy(affineXBytes, 0, encodedBytes, size - affineXBytes.length + 1, affineXBytes.length);
        System.arraycopy(affineYBytes, 0, encodedBytes, encodedBytes.length - affineYBytes.length, affineYBytes.length);
        return encodedBytes;
    }

    public static ECPoint decodePoint(byte[] encodedBytes, EllipticCurve elliptiCcurve) {
        if (encodedBytes[0] != 0x04) {
            throw new IllegalArgumentException("Only uncompressed format is supported");
        }

        int size = (elliptiCcurve.getField().getFieldSize() + 7) / 8;
        byte affineXBytes[] = new byte[size];
        byte affineYBytes[] = new byte[size];
        System.arraycopy(encodedBytes, 1, affineXBytes, 0, size);
        System.arraycopy(encodedBytes, size + 1, affineYBytes, 0, size);
        return new ECPoint(new BigInteger(1, affineXBytes), new BigInteger(1, affineYBytes));
    }

    public static byte[] stripLeadingZeros(byte[] bytes) {
        int i;
        for (i = 0; i < bytes.length - 1; i++) {
            if (bytes[i] != 0) {
                break;
            }
        }

        if (i == 0) {
            return bytes;
        } else {
            byte stripped[] = new byte[bytes.length - i];
            System.arraycopy(bytes, i, stripped, 0, stripped.length);
            return stripped;
        }
    }
}
