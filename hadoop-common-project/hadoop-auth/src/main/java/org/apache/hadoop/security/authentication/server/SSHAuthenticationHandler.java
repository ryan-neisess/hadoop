/*
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
package org.apache.hadoop.security.authentication.server;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.client.PseudoAuthenticator; // Needs update! Remove when finished
import org.apache.hadoop.security.authentication.client.SSHAuthenticator;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.ietf.jgss.GSSManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.regex.Pattern;

import static org.apache.hadoop.util.PlatformName.IBM_JAVA;

/**
 * The <code>SSHAuthenticationHandler</code> provides an SSH certificate authentication mechanism that accepts
 * the user name specified as a query string parameter.
 * <p>
 * This mimics the model of Hadoop Simple authentication which trust the 'user.name' property provided in
 * the configuration object.
 */
public class SSHAuthenticationHandler implements AuthenticationHandler {

  /**
   * Constant that identifies the authentication mechanism.
   */
  public static final String TYPE = "SSH";

  /**
   * Constant for the configuration property that indicates if anonymous users are allowed.
   */
  public static final String ANONYMOUS_ALLOWED = TYPE + ".anonymous.allowed"; //TODO:Change to anonymous not allowed?

  private static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;

  private static final String SSH_AUTH = "SSHAuth";
  private static Logger LOG = LoggerFactory.getLogger(SSHAuthenticationHandler.class);
  private final Collection<String> whitelist = new HashSet<>();

  private boolean acceptAnonymous;
  private String type;

  /**
   * Creates a Hadoop SSH authentication handler with the default auth-token
   * type, <code>ssh</code>.
   */
  public SSHAuthenticationHandler() {
    this(TYPE);
  }

  /**
   * Creates a Hadoop SSH authentication handler with a custom auth-token
   * type.
   *
   * @param type auth-token type.
   */
  public SSHAuthenticationHandler(String type) {
    this.type = type;
  }

  /**
   * Initializes the authentication handler instance.
   * <p>
   * This method is invoked by the {@link AuthenticationFilter#init} method.
   *
   * @param config configuration properties to initialize the handler.
   *
   * @throws ServletException thrown if the handler could not be initialized.
   */
  @Override
  public void init(Properties config) throws ServletException {
//    acceptAnonymous = Boolean.parseBoolean(config.getProperty(ANONYMOUS_ALLOWED, "false"));
//    try {
//      String principal = config.getProperty(SSHPRINCIPAL); //gets the user
//      if (principal == null || principal.trim().length() == 0) {
//        throw new ServletException("Principal not defined in configuration");
//      }
////      keytab = config.getProperty(KEYTAB, keytab);
////      if (keytab == null || keytab.trim().length() == 0) {
////        throw new ServletException("Keytab not defined in configuration");
////      }
////      File keytabFile = new File(keytab);
////      if (!keytabFile.exists()) {
////        throw new ServletException("Keytab does not exist: " + keytab);
////      }
//
//      // use all SPNEGO principals in the keytab if a principal isn't
//      // specifically configured
//      final String[] SSHPrincipals;
//      if (principal.equals("*")) {
//        SSHPrincipals = .getPrincipalNames(
//                keytab, Pattern.compile("HTTP/.*"));
//        if (spnegoPrincipals.length == 0) {
//          throw new ServletException("Principals do not exist in the keytab");
//        }
//      } else {
//        spnegoPrincipals = new String[]{principal};
//      }
//      KeyTab keytabInstance = KeyTab.getInstance(keytabFile);
//      serverSubject.getPrivateCredentials().add(keytabInstance);
//      for (String spnegoPrincipal : spnegoPrincipals) {
//        Principal krbPrincipal = new KerberosPrincipal(spnegoPrincipal);
//        LOG.info("Using keytab {}, for principal {}",
//                keytab, krbPrincipal);
//        serverSubject.getPrincipals().add(krbPrincipal);
//      }
//      String nameRules = config.getProperty(NAME_RULES, null);
//      if (nameRules != null) {
//        KerberosName.setRules(nameRules);
//      }
//      String ruleMechanism = config.getProperty(RULE_MECHANISM, null);
//      if (ruleMechanism != null) {
//        KerberosName.setRuleMechanism(ruleMechanism);
//      }
//
//      final String whitelistStr = config.getProperty(ENDPOINT_WHITELIST, null);
//      if (whitelistStr != null) {
//        final String[] strs = whitelistStr.trim().split("\\s*[,\n]\\s*");
//        for (String s: strs) {
//          if (s.isEmpty()) continue;
//          if (ENDPOINT_PATTERN.matcher(s).matches()) {
//            whitelist.add(s);
//          } else {
//            throw new ServletException(
//                    "The element of the whitelist: " + s + " must start with '/'"
//                            + " and must not contain special characters afterwards");
//          }
//        }
//      }
//
//      try {
//        gssManager = Subject.doAs(serverSubject,
//                new PrivilegedExceptionAction<GSSManager>() {
//                  @Override
//                  public GSSManager run() throws Exception {
//                    return GSSManager.getInstance();
//                  }
//                });
//      } catch (PrivilegedActionException ex) {
//        throw ex.getException();
//      }
//    } catch (Exception ex) {
//      throw new ServletException(ex);
//    }
  }

  /**
   * Returns if the handler is configured to support anonymous users.
   *
   * @return if the handler is configured to support anonymous users.
   */
  protected boolean getAcceptAnonymous() {
    return acceptAnonymous;
  }

  /**
   * Releases any resources initialized by the authentication handler.
   * <p>
   * This implementation does a NOP.
   */
  @Override
  public void destroy() {
  }

  /**
   * Returns the authentication type of the authentication handler, 'simple'.
   *
   * @return the authentication type of the authentication handler, 'simple'.
   */
  @Override
  public String getType() {
    return type;
  }

  /**
   * This is an empty implementation, it always returns <code>TRUE</code>.
   *
   *
   *
   * @param token the authentication token if any, otherwise <code>NULL</code>.
   * @param request the HTTP client request.
   * @param response the HTTP client response.
   *
   * @return <code>TRUE</code>
   * @throws IOException it is never thrown.
   * @throws AuthenticationException it is never thrown.
   */
  @Override
  public boolean managementOperation(AuthenticationToken token,
                                     HttpServletRequest request,
                                     HttpServletResponse response)
    throws IOException, AuthenticationException {
    return true;
  }

  private String getUserName(HttpServletRequest request) {
    String queryString = request.getQueryString();
    if(queryString == null || queryString.length() == 0) {
      return null;
    }
    List<NameValuePair> list = URLEncodedUtils.parse(queryString, UTF8_CHARSET);
    if (list != null) {
      for (NameValuePair nv : list) {
        if (PseudoAuthenticator.USER_NAME.equals(nv.getName())) {
          return nv.getValue();
        }
      }
    }
    return null;
  }

  /**
   * TODO:so this authenticates the http client request?
   *
   * Authenticates an HTTP client request.
   * <p>
   * It extracts the {@link PseudoAuthenticator#USER_NAME} parameter from the query string and creates
   * an {@link AuthenticationToken} with it.
   * <p>
   * If the HTTP client request does not contain the {@link PseudoAuthenticator#USER_NAME} parameter and
   * the handler is configured to allow anonymous users it returns the {@link AuthenticationToken#ANONYMOUS}
   * token.
   * <p>
   * If the HTTP client request does not contain the {@link PseudoAuthenticator#USER_NAME} parameter and
   * the handler is configured to disallow anonymous users it throws an {@link AuthenticationException}.
   *
   * @param request the HTTP client request.
   * @param response the HTTP client response.
   *
   * @return an authentication token if the HTTP client request is accepted and credentials are valid.
   *
   * @throws IOException thrown if an IO error occurred.
   * @throws AuthenticationException thrown if HTTP client request was not accepted as an authentication request.
   */
  @Override
  public AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response)
    throws IOException, AuthenticationException {


    // If the request servlet path is in the whitelist,
    // skip SSH authentication and return anonymous token.
    final String path = request.getServletPath();
    for(final String endpoint: whitelist) {
      if (endpoint.equals(path)) {
        return AuthenticationToken.ANONYMOUS;
      }
    }

    AuthenticationToken token = null;
    String authorization = request.getHeader(
            SSHAuthenticator.AUTHORIZATION);

    if (authorization == null || !authorization.startsWith(SSHAuthenticator.NEGOTIATE)) {
      response.setHeader(SSHAuthenticator.WWW_AUTHENTICATE, SSHAuthenticator.NEGOTIATE);
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      if (authorization == null) {
        LOG.trace("SHH starting for url: {}", request.getRequestURL());
      }
      else
      {
        LOG.warn("'" + SSHAuthenticator.AUTHORIZATION +
                "' does not start with '" +
                SSHAuthenticator.NEGOTIATE + "' :  {}", authorization);
      }
    } else {
      authorization = authorization.substring(
              SSHAuthenticator.NEGOTIATE.length()).trim();
      final Base64 base64 = new Base64(0);
      final byte[] clientToken = base64.decode(authorization);
      try {
        final String serverPrincipal = //http://web.mit.edu/dspace-dev/build/wdc/dspace.old/src/org/dspace/jaas/X509LoginModule.java look for principal in here, we based principal on this
                KerberosUtil.getTokenServerName(clientToken);
        if (!serverPrincipal.startsWith("HTTP/")) {
          throw new IllegalArgumentException(
                  "Invalid server principal " + serverPrincipal +
                          "decoded from client request");
        }
      token = Subject.doAs(serverSubject,
              new PrivilegedExceptionAction<AuthenticationToken>() {
                @Override
                public AuthenticationToken run() throws Exception {
                  return runWithPrincipal(serverPrincipal, clientToken,
                          base64, response);
                }
              });
    } catch (PrivilegedActionException ex) {
      if (ex.getException() instanceof IOException) {
        throw (IOException) ex.getException();
      } else {
        throw new AuthenticationException(ex.getException());
      }
    } catch (Exception ex) {
      throw new AuthenticationException(ex);
    }
  }
    return token;
}
}