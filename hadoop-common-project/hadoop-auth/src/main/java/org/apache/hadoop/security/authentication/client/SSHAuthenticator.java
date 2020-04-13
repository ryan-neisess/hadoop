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
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.Principal;
import javax.security.auth.callback.*;
import javax.security.auth.spi.*;

import static org.apache.hadoop.util.PlatformName.IBM_JAVA;

// JAAS PAM WRAPPER! VERY IMPORTANT 
// READ "http://jaas-pam.sourceforge.net/jaas.html"
// import for the JaasPam login module -  NEEDS TO BE DOWNLOADED AND ADDED TO THE PATH
// import ch.odi.jaaspam;

 /**
 * The {@link SSHAuthenticator} implements the SSH certificate authentication sequence.
 * <p>
 * It uses the default certificate set through CertificateUtil.
 * <p>
 * It falls back to the {@link PseudoAuthenticator} if it fails to register a valid certificate.
 */
public class SSHAuthenticator implements Authenticator {

    // static {
    //     try{
    //         System.load("/usr/lib/pam/pam-ussh.so");
    //     } catch (UnsatisfiedLinkError e) {
    //         System.err.println("Native code library failed to load.\n" + e);
    //         System.exit(1);
    //     }
    // }
    

    private static Logger LOG = LoggerFactory.getLogger(SSHAuthenticator.class);

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

     /*
    * Defines the SSH Certificate configuration that will be used to obtain the Certificate principal
    * from the Certificate Cache.
    *
    * Lists the LoginModules that will be called by the LoginContext. This is where we want to use pam-ussh??
    */
    private static class SSHConfiguration extends Configuration {
        // NEED TO BUILD OUR OWN LOGIN MODULE AND GIVE IT TO OS_LOGIN_MODULE_NAME;
        // NEEDS TO USE THE LINUX-PAM MODULE WITH SSH, HOW? IDK

        // NEED TO SET SSH_AUTH_SOCK HERE
        private static final String OS_LOGIN_MODULE_NAME;
        private static final boolean windows = System.getProperty("os.name").startsWith("Windows");
        private static final boolean is64Bit = System.getProperty("os.arch").contains("64");
        private static final boolean aix = System.getProperty("os.name").equals("AIX");

        // THESE ARE THE REQUIRED LOGIN MODULES THAT HAVE TO PASS ALWAYS
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

        // Give it to the configuration in the format "LoginModule, requirements, options"
        private static final AppConfigurationEntry OS_SPECIFIC_LOGIN =
            new AppConfigurationEntry(OS_LOGIN_MODULE_NAME,
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                new HashMap<String, String>());

        private static final Map<String, String> USER_SSH_OPTIONS = new HashMap<String, String>();

        // NOW WE BUILD OUR OWN CONFIGURATION FOR SSH THAT IS OPTIONAL IN PASSING
        static {
            //This could be /etc/ssh/trusted_user_ca but I think its SSH_AUTH_SOCK
            String ticketCache = System.getenv("SSH_AUTH_SOCK");
            if (IBM_JAVA) {
                USER_SSH_OPTIONS.put("useDefaultCcache", "true");
            } else {
                USER_SSH_OPTIONS.put("doNotPrompt", "true");
                USER_SSH_OPTIONS.put("useTicketCache", "true");
            }
            if (ticketCache != null) {
                if (IBM_JAVA) {
                // The first value searched when "useDefaultCcache" is used.
                System.setProperty("SSH_AUTH_SOCK", ticketCache);
                } else {
                USER_SSH_OPTIONS.put("ticketCache", ticketCache);
                }
            }
            // This is just a ticket renewal thing, so could probably stay
            USER_SSH_OPTIONS.put("renewTGT", "true");

            // THIS IS FOR THE JAAS PAM MODULE. WE NEED TO CREATE A CONFIG FILE CALLED SSH-LOGIN THAT CONTAINS 
            // PAM-USSH.SO IN THE FORMAT "AUTH OPTIONAL PAM-USSH.SO OTHER OPTIONS ABOUT THE USING PAM-USSH.SO"
            USER_SSH_OPTIONS.put("service", "ssh-login");

            // ACCORDING TO UBER-PAM THE SSH-LOGIN CONFIG FILE SHOULD HAVE THIS:
            // "auth [success=1 default=ignore] /lib/security/pam_ussh.so ca_file=/etc/ssh/user_ca authorized_principals_file=/etc/ssh/root_authorized_principals"

            // and should look like
            // ssh-login {
            //     auth [success=1 default=ignore] /lib/security/pam_ussh.so ca_file=/etc/ssh/user_ca authorized_principals_file=/etc/ssh/root_authorized_principals
            // }
        }

        // IT MIGHT BE "/usr/lib/pam/pam-ussh.so"
        // /lib/security/pam-ussh.so
        // SHOULD I REPLACE THE SLASHES WITH .?
        // Now we set out own login here
        private static final AppConfigurationEntry USER_SSH_LOGIN =
            new AppConfigurationEntry("ch.odi.jaaspam.PamLoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,
                                USER_SSH_OPTIONS);

        private static final AppConfigurationEntry[] USER_SSH_CONF =
            new AppConfigurationEntry[]{OS_SPECIFIC_LOGIN, USER_SSH_LOGIN};

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
            return USER_SSH_CONF;
        }
    }



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
                // If the JDK already did the SSH authentication for us pull the token
                AuthenticatedURL.extractToken(conn, token);
                //Check if the token is SSH or x509??? and return??
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
    * Check if the passed token is of type "X.509"
    * I am not sure what other certificate it would be, so right now it should only be X.509
    */
    private boolean isTokenCert(AuthenticatedURL.Token token) throws AuthenticationException {
        if (token.isSet()) {
            AuthToken aToken = AuthToken.parse(token.toString());          
            if (aToken.getType().equals("X.509")) {              
                return true;
            }
        }
        return false;
    }

    /*
    * Indicates if the response is starting an SSH negotiation.
    */
    private boolean isNegotiate(HttpURLConnection conn) throws IOException {
        boolean negotiate = false;
        if (conn.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
            String authHeader = conn.getHeaderField(WWW_AUTHENTICATE);
            negotiate = authHeader != null && authHeader.trim().startsWith(NEGOTIATE);
        }
        return negotiate;
    }

    /**
    * Implements the SSH authentication sequence interaction using the current default principal
    * in the Kerberos cache (normally set via kinit).
    *
    * @param token the authentication token being used for the user.
    *
    * @throws IOException if an IO error occurred.
    * @throws AuthenticationException if an authentication error occurred.
    */
    private void doSSHAuth(final AuthenticatedURL.Token token) throws IOException, AuthenticationException {
        try {
            AccessControlContext context = AccessController.getContext();
            Subject subject = Subject.getSubject(context);

            //Check if subject was received, and if it actually has X.509 certs or certs at all
            // SHOULD IT BE GETPRIVATECREDENTIALS??? OR GETPUBLICCREDENTIALS???
            // SHOULD IT BE X.509CERTIFICATE.CLASS OR JUST CERTIFICATE.CLASS???
            if (subject == null || subject.getPublicCredentials(Certificate.class).isEmpty()) {
                LOG.debug("No subject in context, logging in.");
                subject = new Subject();
                ////////////////////////////////// FIX THIS HERE ///////////////////////////////////////
                // This is where we need an SSHConfiguration() for NEW SSHCONFIGURATION()
                // The SSHConfiguration() SPECIFIES which LoginModule to use to login. We most likely
                // have to build a certificate based login module
                // We also would probably want to give it a CallBackHandler. The reason is because
                // kerberos just sets up stuff to ask for information later in the doAs command, but
                // we want to handle everything in our login module!!!!
                // must pass in the pam module that we want to use in name to the sshconfiguration
                // Where null is, we might need to make our callback handler???
                LoginContext login = new LoginContext("", subject, null, new SSHConfiguration());
                // LoginContext login = new LoginContext("pam-ussh", subject, null);
                login.login();
            }
            // At this point, the subject should be logged in
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using subject: " + subject);
            }
            // KERBEROS ONLY DOES THIS BECAUSE THEY STILL HAVE TO AUTHENTICATE STUFF
            // Here, we are overriding the PrivilegedExceptionAction's run method, providing it the subject
            // What I think we want to do is to compare the things to authenticate the subject
            // Basically, we are verifying now! VERIFY WITH LOADED CERTS??? OR COMMIT???
            // DO WE EVEN NEED THE DO AS PART SINCE ITS ALREADY LOADED IN?????
            // WE DO NEED THIS!! IF YOU LOOK UP THE ORACLE DOCS FOR LOGIN SEQUENCES IT EXPLAINS IT?????
            // Subject.doAs(subject, new PrivilegedExceptionAction<Void>() {
            //     @Override
            //     public Void run() throws Exception {
            //     }
            // });
        } catch (LoginException ex) {
            throw new AuthenticationException(ex);
        }
    }
}