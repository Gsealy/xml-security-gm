package cn.com.infosec.ipp;

public class IPPJNI {

  public native byte[] sm3(byte[] data);

  public native byte[] sm2sign(byte[] dgst, byte[] privKey);

  public native int sm2verify(byte[] dgst, byte[] sig, byte[] pubkey);
  
}
