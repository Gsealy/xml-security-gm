/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.test.dom.keys.content.x509;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.xml.security.test.dom.TestUtils;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Certificate parsing test.
 *
 */
public class XMLX509CertificateTest {

    private static final String BASEDIR =
        System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
    private static final String SEP = System.getProperty("file.separator");

    @org.junit.jupiter.api.Test
    public void testGetX509Certificate() throws Exception {
        File f = new File(BASEDIR + SEP + "src/test/resources" + SEP + "ie" + SEP + "baltimore" +
            SEP + "merlin-examples" + SEP + "merlin-xmldsig-twenty-three" +
            SEP + "signature-x509-crt.xml");

        FileInputStream fis = new FileInputStream(f);
        Document doc = XMLUtils.read(fis, false);
        NodeList nl = doc.getElementsByTagNameNS
                (Constants.SignatureSpecNS, "X509Certificate");
        XMLX509Certificate xmlCert =
            new XMLX509Certificate((Element) nl.item(0), "");
        xmlCert.getX509Certificate();
        // System.out.println(cert);
    }

    @org.junit.jupiter.api.Test
    public void testGetX509CertificateWithCustomProvider() throws Exception {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        File f = new File(BASEDIR + SEP + "src/test/resources" + SEP + "com" + SEP + "provider" +
                SEP + "x509-cert-need-provider.xml");

        FileInputStream fis = new FileInputStream(f);
        Document doc = XMLUtils.read(fis, false);
        NodeList nl = doc.getElementsByTagNameNS
                (Constants.SignatureSpecNS, "X509Certificate");
        XMLX509Certificate xmlCert =
                new XMLX509Certificate((Element) nl.item(0), "");
        X509Certificate x509Certificate = xmlCert.getX509Certificate();
        assertTrue(x509Certificate instanceof BCX509Certificate);
    }

    @org.junit.jupiter.api.Test
    public void testEqualsAndHashCode() throws Exception {
        File f = null;
        if (BASEDIR != null && BASEDIR.length() != 0) {
            f = new File(BASEDIR + SEP +
                    "src/test/resources/ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three/certs/lugh.crt");
        } else {
            f = new File(
                    "src/test/resources/ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three/certs/lugh.crt");
        }

        FileInputStream fis = new FileInputStream(f);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);

        XMLX509Certificate x509Cert1 = new XMLX509Certificate(TestUtils.newDocument(), cert);
        XMLX509Certificate x509Cert2 = new XMLX509Certificate(TestUtils.newDocument(), cert);

        assertEquals(x509Cert1, x509Cert2);
        assertEquals(x509Cert1.hashCode(), x509Cert2.hashCode());
    }


}
