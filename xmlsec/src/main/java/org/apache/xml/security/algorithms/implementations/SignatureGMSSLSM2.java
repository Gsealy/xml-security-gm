package org.apache.xml.security.algorithms.implementations;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import cn.com.infosec.gmssl.GmSSL;

public abstract class SignatureGMSSLSM2 extends SignatureAlgorithmSpi {

  private static final org.slf4j.Logger LOG =
      org.slf4j.LoggerFactory.getLogger(SignatureGMSSLSM2.class);

  private final GmSSL gmssl = new GmSSL();

  public abstract String engineGetURI();

  private final String signAlg = "sm2sign";
  // private final String digestAlg = "SM3";
  // private byte[] digestValue;
  // private byte[] signValue;

  private byte[] publicKey;

  private byte[] digest;

  private byte[] signdata;

  private byte[] privateKey;

  public static byte[] convertXMLDSIGtoASN1(byte xmldsigBytes[]) throws IOException {
    return ECDSAUtils.convertXMLDSIGtoASN1(xmldsigBytes);
  }

  public static byte[] convertASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {
    return ECDSAUtils.convertASN1toXMLDSIG(asn1Bytes);
  }

  public SignatureGMSSLSM2() {}

  protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
    try {
      byte[] jcebytes = SignatureECDSA.convertXMLDSIGtoASN1(signature);

      if (LOG.isDebugEnabled()) {
        LOG.debug("Called ECSM2.verify() on " + Base64.getMimeEncoder().encodeToString(signature));
      }
      // XXX digest 无法计算
      int vret = gmssl.verify(signAlg, digest, jcebytes, publicKey);
      return vret != 1 ? false : true;
    } catch (IOException ex) {
      throw new XMLSignatureException(ex);
    }
  }

  protected void engineSetParameter(AlgorithmParameterSpec params) throws XMLSignatureException {

  }

  /**
   * init Verify with Public Key (for GmSSL)
   * 
   */
  protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
    if (publicKey == null) {
      throw new NullPointerException("Public key is null");
    }

    if (publicKey instanceof PublicKey) {
      this.publicKey = publicKey.getEncoded();
    } else {
      String supplied = null;
      if (publicKey != null) {
        supplied = publicKey.getClass().getName();
      }
      String needed = PublicKey.class.getName();
      Object exArgs[] = {supplied, needed};
      throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
    }
  }

  /**
   * Sign data with GmSSL
   */
  protected byte[] engineSign() throws XMLSignatureException {
    try {
      // signAlg default
      // signdata from 
      byte jcebytes[] = this.gmssl.sign(signAlg, signdata, privateKey);

      return SignatureECDSA.convertASN1toXMLDSIG(jcebytes);
    } catch (IOException ex) {
      throw new XMLSignatureException(ex);
    }
  }

  protected void engineInitSign(Key privateKey, SecureRandom secureRandom)
      throws XMLSignatureException {
    if (privateKey == null) {
      throw new NullPointerException("Public key is null");
    }
    if (privateKey instanceof PrivateKey) {
      this.privateKey = privateKey.getEncoded();
    } else {
      String supplied = null;
      if (privateKey != null) {
        supplied = privateKey.getClass().getName();
      }
      String needed = PrivateKey.class.getName();
      Object exArgs[] = {supplied, needed};
      throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
    }
  }

  protected void engineInitSign(Key privateKey) throws XMLSignatureException {
    engineInitSign(privateKey, (SecureRandom) null);
  }
  
  protected void engineUpdate(byte[] input) throws XMLSignatureException {
    
  }

  protected void engineUpdate(byte input) throws XMLSignatureException {}

  protected void engineUpdate(byte buf[], int offset, int len) throws XMLSignatureException {}

  protected String engineGetJCEAlgorithmString() {
    return "EC";
  }

  protected String engineGetJCEProviderName() {
    return "GmSSL";
  }

  protected void engineSetHMACOutputLength(int HMACOutputLength) throws XMLSignatureException {
    throw new XMLSignatureException("algorithms.HMACOutputLengthOnlyForHMAC");
  }

  protected void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec)
      throws XMLSignatureException {
    throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnRSA");
  }

  /**
   * Class SignatureECSM2SM3
   *
   */
  public static class SignatureECSM2SM3_GMSSL extends SignatureGMSSLSM2 {

    /**
     * Constructor SignatureECSM2SM3
     *
     * @throws XMLSignatureException
     */
    public SignatureECSM2SM3_GMSSL() throws XMLSignatureException {
      super();
    }

    /** {@inheritDoc} */
    public String engineGetURI() {
      return XMLSignature.ALGO_ID_SIGNATURE_ECSM2_SM3_GMSSL;
    }

  }
}
