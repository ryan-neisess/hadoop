/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.security.authentication.util;

import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;

public class CertificateUtil {
  private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----\n";
  private static final String PEM_FOOTER = "\n-----END CERTIFICATE-----";

  /**
   * Gets an RSAPublicKey from the provided PEM encoding.
   *
   * @param pem
   *          - the pem encoding from config without the header and footer
   * @return RSAPublicKey the RSA public key
   * @throws ServletException thrown if a processing error occurred
   */
  public static RSAPublicKey parseRSAPublicKey(String pem) throws ServletException {
    String fullPem = PEM_HEADER + pem + PEM_FOOTER;
    PublicKey key = null;
    try {
      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream is = new ByteArrayInputStream(
          fullPem.getBytes(StandardCharsets.UTF_8));

      X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
      key = cer.getPublicKey();
    } catch (CertificateException ce) {
      String message = null;
      if (pem.startsWith(PEM_HEADER)) {
        message = "CertificateException - be sure not to include PEM header "
            + "and footer in the PEM configuration element.";
      } else {
        message = "CertificateException - PEM may be corrupt";
      }
      throw new ServletException(message, ce);
    }
    return (RSAPublicKey) key;
  }

  /**
   * Get all the unique principals present in the keytabfile.
   *
   * @param sshFileName
   *          Name of the ssh file to be read.
   * @return list of unique principals in the keytab.
   * @throws IOException
   *          If keytab entries cannot be read from the file.
   */
  public static final String[] getPrincipalNames(String sshFileName) throws IOException {
    Keytab keytab = Keytab.loadKeytab(new File(sshFileName));
    Set<String> principals = new HashSet<String>();
    List<PrincipalName> entries = keytab.getPrincipals();
    for (PrincipalName entry : entries) {
      principals.add(entry.getName().replace("\\", "/"));
    }
    return principals.toArray(new String[0]);
  }
}


