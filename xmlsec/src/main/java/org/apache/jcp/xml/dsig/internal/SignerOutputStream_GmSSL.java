/**
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
/*
 * $Id: SignerOutputStream.java, v 1.2 2005/09/15 14:29:02 mullan Exp $
 */
package org.apache.jcp.xml.dsig.internal;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import cn.com.infosec.ipp.IPPJNI;

/**
 * Derived from Apache sources and changed to use java.security.Signature objects as input instead
 * of org.apache.xml.security.algorithms.SignatureAlgorithm objects.
 *
 */
public class SignerOutputStream_GmSSL extends ByteArrayOutputStream {
  private final IPPJNI ipp;
  // private final GmSSL gmssl;
  private byte[] update;
  // private final String digestAlg = "SM3";
  // private final String signAlg = "sm2sign";
  private byte[] priv;
  private byte[] pub;

  public SignerOutputStream_GmSSL(IPPJNI ipp) {
    this.ipp = ipp;
    this.update = null;
    this.priv = null;
    this.pub = null;
  }

  @Override
  public void write(int arg0) {
    super.write(arg0);
    byte[] cache = new byte[1];
    cache[0] = (byte) arg0;
    this.update = cache;
  }

  @Override
  public void write(byte[] arg0, int arg1, int arg2) {
    super.write(arg0, arg1, arg2);
    this.update = arg0;
  }

  public void initKey(Key pkey) {
    if (pkey instanceof BCECPrivateKey) {
      BCECPrivateKey priv = (BCECPrivateKey) pkey;
      this.priv = priv.getD().toByteArray();
    } else if (pkey instanceof BCECPublicKey) {
      byte[] data = pkey.getEncoded();
      setPublicKey(data);
    }
  }

  public byte[] getSignValue() {
    if (priv == null || update == null) {
      throw new NullPointerException("priv key or data is null");
    }
    return ipp.sm2sign(update, priv);
  }

  public boolean getVerify(byte[] sig) {
    if (pub == null || update == null) {
      throw new NullPointerException("Pub key or data is null");
    }
    return ipp.sm2verify(update, sig, pub) == 1;
  }

  /** 暂时只针对SM2公钥 */
  private void setPublicKey(byte[] data) {
    int j = 0;
    for (int i = 0; i < data.length; i++) {
      if (data[i] == 0x03 && data[i + 1] == 0x42 && data[i + 2] == 0x00) {
        j = i + 3;
      }
    }
    byte[] dest = new byte[65];
    System.arraycopy(data, j, dest, 0, 65);
    this.pub = dest;
  }
}
