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
package org.apache.hadoop.security.authentication.server;

import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.client.PseudoAuthenticator; // Needs update! Remove when finished
import org.apache.hadoop.security.authentication.client.SSHAuthenticator;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Properties;

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
  public static final String TYPE = "ssh";

  /**
   * Constant for the configuration property that indicates if anonymous users are allowed.
   */
  private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");

  private static final String SSH_AUTH = "SSHAuth";

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
    acceptAnonymous = Boolean.parseBoolean(config.getProperty(ANONYMOUS_ALLOWED, "false"));
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

  /**
   * Needs Update!
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
    AuthenticationToken token;
    String userName = getUserName(request);
    if (userName == null) {
      if (getAcceptAnonymous()) {
        token = AuthenticationToken.ANONYMOUS;
      } else {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader(WWW_AUTHENTICATE, PSEUDO_AUTH);
        token = null;
      }
    } else {
      token = new AuthenticationToken(userName, userName, getType());
    }
    return token;
  }

}
