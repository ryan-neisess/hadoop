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

    private static Logger LOG = LoggerFactory.getLogger(SSHAuthenticator.class);

    private URL url;
    private Base64 base64;
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

    /**
     * CA certificate
     */
    // private PublicKey caPublicKey;
    private static final PublicKey caPublicKey = new CertificateUtil().parseRSAPublicKey(new Base64(0));

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

    /*
    * Defines the SSH configuration that will be used to obtain the X.509 principal from the
    * cache.
    */
    private static class SSHConfiguration extends Configuration {
        //Needs to be initialized. Probably put the login with callback handler here
        private static final String OS_LOGIN_MODULE_NAME;
        private static final boolean windows = System.getProperty("os.name").startsWith("Windows");
        private static final boolean is64Bit = System.getProperty("os.arch").contains("64");
        private static final boolean aix = System.getProperty("os.name").equals("AIX");
    
        /* Return the OS login module class name */
        private static String getOSLoginModuleName() {
          if (IBM_JAVA) {
            if (windows) {
              return is64Bit ? "com.ibm.security.auth.module.Win64LoginModule"
                  : "com.ibm.security.auth.module.NTLoginModule";
            } else if (aix) {
              return is64Bit ? "com.ibm.security.auth.module.AIX64LoginModule"
                  : "com.ibm.security.auth.module.AIXLoginModule";
            } else {
              return "com.ibm.security.auth.module.LinuxLoginModule";
            }
          } else {
            return windows ? "com.sun.security.auth.module.NTLoginModule"
                : "com.sun.security.auth.module.UnixLoginModule";
          }
        }
    
        static {
          OS_LOGIN_MODULE_NAME = getOSLoginModuleName();
        }
    
        private static final AppConfigurationEntry OS_SPECIFIC_LOGIN =
          new AppConfigurationEntry(OS_LOGIN_MODULE_NAME,
                                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                    new HashMap<String, String>());
    
        private static final Map<String, String> USER_CERTIFICATE_OPTIONS = new HashMap<String, String>();
        // private static final PublicKey caPublicKey = new CertificateUtil();
        static {
            //SHOULD GET SSH CERTIFICATE CACHE
            String ticketCache = System.getenv("SSH_AUTH_SOCK");
            if (IBM_JAVA) {
                USER_CERTIFICATE_OPTIONS.put("useDefaultCcache", "true");
            } else {
                USER_CERTIFICATE_OPTIONS.put("doNotPrompt", "true");
                USER_CERTIFICATE_OPTIONS.put("useTicketCache", "true");
            }
            if (ticketCache != null) {
                if (IBM_JAVA) {
                // The first value searched when "useDefaultCcache" is used.
                System.setProperty("SSH_AUTH_SOCK", ticketCache);
                } else {
                    USER_CERTIFICATE_OPTIONS.put("ticketCache", ticketCache);
                }
            }
            USER_CERTIFICATE_OPTIONS.put("renewTGT", "true");
            //Add public key of certificate
            // USER_CERTIFICATE_OPTIONS.put("ca.public.key", CertificateUtil.parseRSAPublicKey())
            USER_CERTIFICATE_OPTIONS.put("ca.certificate.type", "X.509");
        }
    
        private static final AppConfigurationEntry USER_CERTIFICATE_LOGIN =
          new AppConfigurationEntry(CertificateUtil.getPublicKey(),
                                    AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,
                                    USER_CERTIFICATE_OPTIONS);
    
        private static final AppConfigurationEntry[] USER_CERTIFICATE_CONF =
          new AppConfigurationEntry[]{OS_SPECIFIC_LOGIN, USER_CERTIFICATE_LOGIN};
    
        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
          return USER_CERTIFICATE_CONF;
        }
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
        if (!token.isSet()) {
            this.url = url;
            base64 = new Base64(0);
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
                // doSSHAuth(token);
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
    @VisibleForTesting
    static <T extends Exception> T wrapExceptionWithMessage(T exception, String msg) {
        Class<? extends Throwable> exceptionClass = exception.getClass();
        try {
            Constructor<? extends Throwable> ctor = exceptionClass.getConstructor(String.class);
            Throwable t = ctor.newInstance(msg);
            return (T) (t.initCause(exception));
        } catch (Throwable e) {
            LOG.debug("Unable to wrap exception of type {}, it has "
                + "no (String) constructor.", exceptionClass, e);
            return exception;
        }
    }

    /**
   * If the specified URL does not support SSH authentication, a fallback {@link Authenticator} will be used.
   * <p>
   * This implementation returns a {@link PseudoAuthenticator}.
   *
   * @return the fallback {@link Authenticator}.
   */
    protected Authenticator getFallBackAuthenticator() {
        Authenticator auth = new PseudoAuthenticator();
        if (connConfigurator != null) {
            auth.setConnectionConfigurator(connConfigurator);
        }
        return auth;
    }

    /*
   * Check if the passed token is of type "cert" or "kerberos-dt"
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

    /*
    * Indicates if the response is starting a SSH negotiation.
    */
    private boolean isNegotiate(HttpURLConnection conn) throws IOException {
        boolean negotiate = false;
        if (conn.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
            String authHeader = conn.getHeaderField(WWW_AUTHENTICATE);
            negotiate = authHeader != null && authHeader.trim().startsWith(NEGOTIATE);
        }
        return negotiate;
    }
}