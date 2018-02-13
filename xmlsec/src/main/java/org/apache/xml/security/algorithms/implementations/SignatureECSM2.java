package org.apache.xml.security.algorithms.implementations;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

public abstract class SignatureECSM2 extends SignatureAlgorithmSpi {

  private static final org.slf4j.Logger LOG =
      org.slf4j.LoggerFactory.getLogger(SignatureECSM2.class);

  private Signature signatureAlgorithm;

  public abstract String engineGetURI();

  public static byte[] convertXMLDSIGtoASN1(byte xmldsigBytes[]) throws IOException {
    return ECDSAUtils.convertXMLDSIGtoASN1(xmldsigBytes);
  }
  
  public static byte[] convertASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {
    return ECDSAUtils.convertASN1toXMLDSIG(asn1Bytes);
  }
  
  public SignatureECSM2() throws XMLSignatureException {
    String algorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());

    LOG.debug("Created SignatureECSM2 using {}", algorithmID);
    String provider = JCEMapper.getProviderId();
    try {
      if (provider == null) {
        this.signatureAlgorithm = Signature.getInstance(algorithmID);
      } else {
        this.signatureAlgorithm = Signature.getInstance(algorithmID, provider);
      }
    } catch (java.security.NoSuchAlgorithmException ex) {
      Object[] exArgs = {algorithmID, ex.getLocalizedMessage()};

      throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
    } catch (NoSuchProviderException ex) {
      Object[] exArgs = {algorithmID, ex.getLocalizedMessage()};

      throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
    }
  }

  protected void engineSetParameter(AlgorithmParameterSpec params)
      throws XMLSignatureException {
      try {
          this.signatureAlgorithm.setParameter(params);
      } catch (InvalidAlgorithmParameterException ex) {
          throw new XMLSignatureException(ex);
      }
  }

  protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
      try {
          byte[] jcebytes = SignatureECDSA.convertXMLDSIGtoASN1(signature);

          if (LOG.isDebugEnabled()) {
              LOG.debug("Called ECSM2.verify() on " + Base64.getMimeEncoder().encodeToString(signature));
          }

          return this.signatureAlgorithm.verify(jcebytes);
      } catch (SignatureException ex) {
          throw new XMLSignatureException(ex);
      } catch (IOException ex) {
          throw new XMLSignatureException(ex);
      }
  }

  protected void engineInitVerify(Key publicKey) throws XMLSignatureException {

      if (!(publicKey instanceof PublicKey)) {
          String supplied = null;
          if (publicKey != null) {
              supplied = publicKey.getClass().getName();
          }
          String needed = PublicKey.class.getName();
          Object exArgs[] = { supplied, needed };

          throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
      }

      try {
          this.signatureAlgorithm.initVerify((PublicKey) publicKey);
      } catch (InvalidKeyException ex) {
          // reinstantiate Signature object to work around bug in JDK
          // see: http://bugs.sun.com/view_bug.do?bug_id=4953555
          Signature sig = this.signatureAlgorithm;
          try {
              this.signatureAlgorithm = Signature.getInstance(signatureAlgorithm.getAlgorithm());
          } catch (Exception e) {
              // this shouldn't occur, but if it does, restore previous
              // Signature
              LOG.debug("Exception when reinstantiating Signature: {}", e);
              this.signatureAlgorithm = sig;
          }
          throw new XMLSignatureException(ex);
      }
  }

  protected byte[] engineSign() throws XMLSignatureException {
      try {
          byte jcebytes[] = this.signatureAlgorithm.sign();

          return SignatureECDSA.convertASN1toXMLDSIG(jcebytes);
      } catch (SignatureException ex) {
          throw new XMLSignatureException(ex);
      } catch (IOException ex) {
          throw new XMLSignatureException(ex);
      }
  }

  protected void engineInitSign(Key privateKey, SecureRandom secureRandom)
      throws XMLSignatureException {
      if (!(privateKey instanceof PrivateKey)) {
          String supplied = null;
          if (privateKey != null) {
              supplied = privateKey.getClass().getName();
          }
          String needed = PrivateKey.class.getName();
          Object exArgs[] = { supplied, needed };

          throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
      }

      try {
          if (secureRandom == null) {
              this.signatureAlgorithm.initSign((PrivateKey) privateKey);
          } else {
              this.signatureAlgorithm.initSign((PrivateKey) privateKey, secureRandom);
          }
      } catch (InvalidKeyException ex) {
          throw new XMLSignatureException(ex);
      }
  }

  protected void engineInitSign(Key privateKey) throws XMLSignatureException {
      engineInitSign(privateKey, (SecureRandom)null);
  }

  protected void engineUpdate(byte[] input) throws XMLSignatureException {
      try {
          this.signatureAlgorithm.update(input);
      } catch (SignatureException ex) {
          throw new XMLSignatureException(ex);
      }
  }

  protected void engineUpdate(byte input) throws XMLSignatureException {
      try {
          this.signatureAlgorithm.update(input);
      } catch (SignatureException ex) {
          throw new XMLSignatureException(ex);
      }
  }

  protected void engineUpdate(byte buf[], int offset, int len) throws XMLSignatureException {
      try {
          this.signatureAlgorithm.update(buf, offset, len);
      } catch (SignatureException ex) {
          throw new XMLSignatureException(ex);
      }
  }

  protected String engineGetJCEAlgorithmString() {
      return this.signatureAlgorithm.getAlgorithm();
  }

  protected String engineGetJCEProviderName() {
      return this.signatureAlgorithm.getProvider().getName();
  }

  protected void engineSetHMACOutputLength(int HMACOutputLength)
      throws XMLSignatureException {
      throw new XMLSignatureException("algorithms.HMACOutputLengthOnlyForHMAC");
  }

  protected void engineInitSign(
      Key signingKey, AlgorithmParameterSpec algorithmParameterSpec
  ) throws XMLSignatureException {
      throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnRSA");
  }

  /**
   * Class SignatureECSM2SM3
   *
   */
  public static class SignatureECSM2SM3 extends SignatureECSM2 {
      /**
       * Constructor SignatureECSM2SM3
       *
       * @throws XMLSignatureException
       */
      public SignatureECSM2SM3() throws XMLSignatureException {
          super();
      }

      /** {@inheritDoc} */
      public String engineGetURI() {
          return XMLSignature.ALGO_ID_SIGNATURE_ECSM2_SM3;
      }
  }
}
