/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

//This should be changed to package org.apache.hadoop.security.authentication.client;
package main.java.org.apache.hadoop.security.authentication.client;

import com.google.common.annotations.VisibleForTesting;
import java.lang.reflect.Constructor;
import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.security.authentication.server.HttpConstants;
import org.apache.hadoop.security.authentication.util.AuthToken;
import org.apache.hadoop.security.authentication.util.CertificateUtil;
import org.apache.hadoop.security.authentication.util.Signer;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import static org.apache.hadoop.util.PlatformName.IBM_JAVA;

/**
 * The {@link SSHAuthenticator} implements the SSH certificate authentication sequence.
 * <p>
 * It uses the default certificate set through CertificateUtil.
 * <p>
 * It falls back to the {@link PseudoAuthenticator} if it fails to register a valid certificate.
 */
public class SSHAuthenticator implements Authenticator {

    private static Logger LOG = LoggerFactory.getLogger(
      SSHAuthenticator.class);

      private ConnectionConfigurator connConfigurator;

    /**
     * Sets a {@link ConnectionConfigurator} instance to use for
     * configuring connections.
     *
     * @param configurator the {@link ConnectionConfigurator} instance.
     */
    @Override
    public void setConnectionConfigurator(ConnectionConfigurator configurator) {
        connConfigurator = configurator;
    }


    /**
     * HTTP header used by the SPNEGO server endpoint during an authentication sequence.
     */
    public static final String WWW_AUTHENTICATE =
        HttpConstants.WWW_AUTHENTICATE_HEADER;

    /**
     * HTTP header used by the SPNEGO client endpoint during an authentication sequence.
     */
    public static final String AUTHORIZATION = HttpConstants.AUTHORIZATION_HEADER;

    /**
     * HTTP header prefix used by the SPNEGO client/server endpoints during an authentication sequence.
     */
    public static final String NEGOTIATE = HttpConstants.NEGOTIATE;

    private static final String AUTH_HTTP_METHOD = "OPTIONS";

    ////////////////////////////////////////
    // Variables
    ////////////////////////////////////////
    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;

    // configurable option
    private boolean debug = false;
    private String caCertificateResource;
    private String caCertificateType = defaultCertificateType;

    // the authentication status
    private boolean succeeded       = false;
    private boolean commitSucceeded = false;

    // other
    /**
     * CA certificate
     */
    private PublicKey caPublicKey;

    /**
     * Principal
     */
    private X509Principal x509Principal;

    /**
     * X509 certificate of user
     */
    private X509Certificate certificate;

    /**
     * Identifier for CA certificate
     */
    private static final String CA_PUBLIC_KEY = "ca.public.key";

    /**
     * Identifier for CA certificate
     */
    private static final String defaultCertificateType = "X.509";

}