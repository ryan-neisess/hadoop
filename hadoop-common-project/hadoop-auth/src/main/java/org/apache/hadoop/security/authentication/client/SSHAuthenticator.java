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

package org.apache.hadoop.security.authentication.client;

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

//Imports for certificate
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.Principal;
import javax.security.auth.callback.*;
import javax.security.auth.spi.*;

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
     * HTTP header used by the SSH server endpoint during an authentication sequence.
     */
    public static final String WWW_AUTHENTICATE =
        HttpConstants.WWW_AUTHENTICATE_HEADER;

    /**
     * HTTP header used by the SSH client endpoint during an authentication sequence.
     */
    public static final String AUTHORIZATION = HttpConstants.AUTHORIZATION_HEADER;

    /**
     * HTTP header prefix used by the SSH client/server endpoints during an authentication sequence.
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

    //Principal doesnt exist as X509... We'd have to make our own class. I found a page on that but I 
    // Dont know if it is really needed so we'll skip that for now 
    /**
     * Principal
     */
    // private X509Principal x509Principal;

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

    /**
     * Initialize this <code>LoginModule</code>.
     *
     * <p>
     *
     * @param subject the <code>Subject</code> to be authenticated. <p>
     *
     * @param callbackHandler a <code>CallbackHandler</code> for communicating
     *			with the end user (prompting for usernames and
    *			passwords, for example). <p>
    *
    * @param sharedState shared <code>LoginModule</code> state. <p>
    *
    * @param options options specified in the login
    *			<code>Configuration</code> for this particular
    *			<code>LoginModule</code>.
    */
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        this.subject         = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState     = sharedState;
        this.options         = options;

        // initialize any configured options 
        //CHANGE THIS TO AUTH_HTTP_METHOD?????????????
        debug = "true".equalsIgnoreCase((String)options.get("debug"));
        
        // FIXME Ultimately we might want to allow multiple CA authorities
        caCertificateResource = (String)options.get("ca.certificate");
        caCertificateType     = (String)options.get("ca.certificate.type");
    }

    /**
     * Performs SSH authentication against the specified URL.
     * <p>
     * If a token is given it does a NOP and returns the given token.
     * <p>
     * If no token is given, it will perform the SSH authentication sequence using an
     * HTTP <code>OPTIONS</code> request.
     *
     * @param url the URl to authenticate against.
     * @param token the authentication token being used for the user.
     *
     * @throws IOException if an IO error occurred.
     * @throws AuthenticationException if an authentication error occurred.
     */
    @Override
    public void authenticate(URL url, AuthenticatedURL.Token token) throws IOException, AuthenticationException {
        // String strUrl = url.toString();
        // String paramSeparator = (strUrl.contains("?")) ? "&" : "?";
        // strUrl += paramSeparator + USER_NAME_EQ + getUserName();
        // url = new URL(strUrl);
        // HttpURLConnection conn = token.openConnection(url, connConfigurator);
        // conn.setRequestMethod("OPTIONS");
        // conn.connect();
        // AuthenticatedURL.extractToken(conn, token);
        if (!token.isSet()) {
            this.url = url;
            try {
              HttpURLConnection conn = token.openConnection(url, connConfigurator);
              conn.setRequestMethod(AUTH_HTTP_METHOD);
              conn.connect();
      
              boolean needFallback = false;
              if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                LOG.debug("JDK performed authentication on our behalf.");
                // If the JDK already did the SPNEGO back-and-forth for
                // us, just pull out the token.
                AuthenticatedURL.extractToken(conn, token);
                if (isTokenCert(token)) {
                  return;
                }
                needFallback = true;
              }
              if (!needFallback && isNegotiate(conn)) {
                LOG.debug("Performing our own SSH Authentication.");
                doSSHAuth(token);
              } else {
                LOG.debug("Using fallback authenticator sequence.");
                Authenticator auth = getFallBackAuthenticator();
                // Make sure that the fall back authenticator have the same
                // ConnectionConfigurator, since the method might be overridden.
                // Otherwise the fall back authenticator might not have the
                // information to make the connection (e.g., SSL certificates)
                auth.setConnectionConfigurator(connConfigurator);
                auth.authenticate(url, token);
              }
            } catch (IOException ex){
              throw wrapExceptionWithMessage(ex,
                  "Error while authenticating with endpoint: " + url);
            } catch (AuthenticationException ex){
              throw wrapExceptionWithMessage(ex,
                  "Error while authenticating with endpoint: " + url);
            }
        }
    }

    /*
   * Check if the passed token is of type "kerberos" or "kerberos-dt"
   */
    private boolean isTokenCert(AuthenticatedURL.Token token) throws AuthenticationException {
        if (token.isSet()) {
            AuthToken aToken = AuthToken.parse(token.toString());          
            if (aToken.getType().equals("ca.certificate") ||
                aToken.getType().equals("kerberos-dt")) {              
                return true;
            }
        }
        return false;
    }
}