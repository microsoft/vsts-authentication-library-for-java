// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.google.common.util.concurrent.ListenableFuture;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.oauth.helpers.MSOpenTechExternalBrowserLauncher;
import com.microsoft.alm.helpers.Action;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.Guid;
import com.microsoft.alm.helpers.HttpClient;
import com.microsoft.alm.helpers.ObjectExtensions;
import com.microsoft.alm.helpers.QueryString;
import com.microsoft.alm.helpers.StringContent;
import com.microsoft.alm.helpers.StringHelper;
import com.microsoft.alm.helpers.UriHelper;
import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.oauth2.useragent.AuthorizationResponse;
import com.microsoft.alm.oauth2.useragent.UserAgent;
import com.microsoft.alm.oauth2.useragent.UserAgentImpl;
import com.microsoft.alm.secret.TokenPair;
import com.microsoftopentechnologies.auth.AuthenticationContext;
import com.microsoftopentechnologies.auth.AuthenticationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Interfaces with Azure to perform authentication and identity services.
 */
public class AzureAuthority {

    private static final Logger logger = LoggerFactory.getLogger(AzureAuthority.class);

    /**
     * The base URL for logon services in Azure.
     */
    public static final String AuthorityHostUrlBase = "https://login.microsoftonline.com";

    /**
     * Common tenant for discovery of real tenant
     */
    public static final String CommonTenant = "common";

    /**
     * The common Url for logon services in Azure.
     */
    public static final String DefaultAuthorityHostUrl = AuthorityHostUrlBase + "/" + CommonTenant;

    private final UserAgent userAgent;

    private String authorityHostUrl;

    /**
     * Creates a new {@link AzureAuthority} with the default authority host url.
     */
    public AzureAuthority() {
        this(DefaultAuthorityHostUrl);
    }

    /**
     * Creates a new {@link AzureAuthority} with an authority host url.
     *
     * @param authorityHostUrl Non-default authority host url.
     */
    public AzureAuthority(final String authorityHostUrl) {
        this(authorityHostUrl, new UserAgentImpl());
    }

    AzureAuthority(final String authorityHostUrl, final UserAgent userAgent) {
        Debug.Assert(UriHelper.isWellFormedUriString(authorityHostUrl), "The authorityHostUrl parameter is invalid.");
        Debug.Assert(userAgent != null, "The userAgent parameter is null.");

        this.authorityHostUrl = authorityHostUrl;
        this.userAgent = userAgent;
    }

    private URI createAuthorizationEndpointUri(final String authorityHostUrl, final String resource, final String clientId,
                                               final URI redirectUri, final UserIdentifier userId, final String state,
                                               final PromptBehavior promptBehavior, final String queryParameters) {
        final QueryString qs = new QueryString();
        qs.put(OAuthParameter.RESOURCE, resource);
        qs.put(OAuthParameter.CLIENT_ID, clientId);
        qs.put(OAuthParameter.RESPONSE_TYPE, OAuthParameter.CODE);
        qs.put(OAuthParameter.REDIRECT_URI, redirectUri.toString());

        if (!userId.isAnyUser()
                && (userId.getType() == UserIdentifierType.OPTIONAL_DISPLAYABLE_ID
                || userId.getType() == UserIdentifierType.REQUIRED_DISPLAYABLE_ID)) {
            qs.put(OAuthParameter.LOGIN_HINT, userId.getId());
        }

        if (state != null) {
            qs.put(OAuthParameter.STATE, state);
        }

        String promptValue = null;
        switch (promptBehavior) {
            case ALWAYS:
                promptValue = PromptValue.LOGIN;
                break;
            case NEVER:
                promptValue = PromptValue.ATTEMPT_NONE;
                break;
        }
        if (promptValue != null) {
            qs.put(OAuthParameter.PROMPT, promptValue);
        }

        final StringBuilder sb = new StringBuilder(authorityHostUrl);
        sb.append("/oauth2/authorize?");
        sb.append(qs.toString());
        if (!StringHelper.isNullOrWhiteSpace(queryParameters)) {
            // TODO: 449282: ADAL.NET checks if queryParameters contains any duplicate parameters
            int start = (queryParameters.charAt(0) == '&') ? 1 : 0;
            sb.append('&').append(queryParameters, start, queryParameters.length());
        }
        final URI result;
        try {
            result = new URI(sb.toString());
        } catch (final URISyntaxException e) {
            throw new Error(e);
        }
        return result;
    }

    private URI createTokenEndpointUri(final String authorityHostUrl) {
        final StringBuilder sb = new StringBuilder(authorityHostUrl);
        sb.append("/oauth2/token");
        final URI result;
        try {
            result = new URI(sb.toString());
        } catch (final URISyntaxException e) {
            throw new Error(e);
        }
        return result;
    }

    private StringContent createTokenRequest(final String resource, final String clientId, final String authorizationCode,
                                             final URI redirectUri, final UUID correlationId) {
        final QueryString qs = new QueryString();
        qs.put(OAuthParameter.RESOURCE, resource);
        qs.put(OAuthParameter.CLIENT_ID, clientId);
        qs.put(OAuthParameter.GRANT_TYPE, OAuthParameter.AUTHORIZATION_CODE);
        qs.put(OAuthParameter.CODE, authorizationCode);
        qs.put(OAuthParameter.REDIRECT_URI, redirectUri.toString());
        if (correlationId != null && !Guid.Empty.equals(correlationId)) {
            qs.put(OAuthParameter.CORRELATION_ID, correlationId.toString());
            qs.put(OAuthParameter.REQUEST_CORRELATION_ID_IN_RESPONSE, "true");
        }
        final StringContent result = StringContent.createUrlEncoded(qs);
        return result;
    }

    /**
     * Acquires a {@link TokenPair} from the authority via an interactive user logon
     * prompt.
     *
     * @param clientId        Identifier of the client requesting the token.
     * @param resource        Identifier of the target resource that is the recipient of the requested token.
     * @param redirectUri     Address to return to upon receiving a response from the authority.
     * @param queryParameters Optional: appended as-is to the query string in the HTTP authentication request to the
     *                        authority.
     * @return If successful, a {@link TokenPair}; otherwise null.
     */
    public TokenPair acquireToken(final String clientId, final String resource,
                                  final URI redirectUri, String queryParameters) throws AuthorizationException {
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(clientId), "The clientId parameter is null or empty");
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(resource), "The resource parameter is null or empty");
        Debug.Assert(redirectUri != null, "The redirectUri parameter is null");
        Debug.Assert(redirectUri.isAbsolute(), "The redirectUri parameter is not an absolute Uri");

        logger.debug("AzureAuthority::acquireToken");

        final UUID correlationId = null;
        TokenPair tokens = null;
        queryParameters = ObjectExtensions.coalesce(queryParameters, StringHelper.Empty);

        final String authorizationCode = acquireAuthorizationCode(resource, clientId, redirectUri, queryParameters);
        if (authorizationCode == null) {
            logger.debug("   token acquisition failed.");
            return tokens;
        }

        final HttpClient client = new HttpClient(Global.getUserAgent());
        try {
            final URI tokenEndpoint = createTokenEndpointUri(authorityHostUrl);
            final StringContent requestContent = createTokenRequest(resource, clientId, authorizationCode, redirectUri, correlationId);
            final HttpURLConnection connection = client.post(tokenEndpoint, requestContent, new Action<HttpURLConnection>() {
                @Override
                public void call(final HttpURLConnection conn) {
                    conn.setUseCaches(false);
                }
            });
            client.ensureOK(connection);
            final String responseContent = HttpClient.readToString(connection);
            tokens = new TokenPair(responseContent);

            logger.debug("   token acquisition succeeded.");
        } catch (final IOException e) {
            // TODO: 449248: silently catching the exception here seems horribly wrong
            logger.debug("   token acquisition failed.");
            logger.debug("   IOException: {}", e);
        }
        return tokens;
    }

    private String acquireAuthorizationCode(final String resource, final String clientId, final URI redirectUri,
                                            final String queryParameters) throws AuthorizationException {
        final String expectedState = UUID.randomUUID().toString();
        String authorizationCode = null;
        final URI authorizationEndpoint = createAuthorizationEndpointUri(authorityHostUrl, resource, clientId,
                redirectUri, UserIdentifier.ANY_USER, expectedState, PromptBehavior.ALWAYS, queryParameters);
        final AuthorizationResponse response = userAgent.requestAuthorizationCode(authorizationEndpoint, redirectUri);
        authorizationCode = response.getCode();
        // verify that the authorization response gave us the state we sent in the authz endpoint URI
        final String actualState = response.getState();
        if (!expectedState.equals(actualState)) {
            // the states are somehow different; better to assume malice and ignore the authz code
            authorizationCode = null;
        }
        return authorizationCode;
    }


    /**
     * Retrieve an Azure Active Directory backed OAuth token based on MSOpenTech's SWT implementation.
     *
     * @param clientId        Identifier of the client requesting the token.
     * @param resource        Identifier of the target resource that is the recipient of the requested token.
     * @param redirectUri     Address to return to upon receiving a response from the authority.
     *
     * @return an authentication result which encloses an access token
     *
     * @throws IOException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    public AuthenticationResult acquireAuthenticationResult(final String clientId, final String resource,
                                                            final URI redirectUri) throws
            IOException, ExecutionException, InterruptedException, AuthorizationException {
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(clientId), "The clientId parameter is null or empty");
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(resource), "The resource parameter is null or empty");
        Debug.Assert(redirectUri != null, "The redirectUri parameter is null");
        Debug.Assert(redirectUri.isAbsolute(), "The redirectUri parameter is not an absolute Uri");

        logger.info("Acquiring AuthenticationInfo by SWT library");

        final AuthenticationContext context = new AuthenticationContext("login.microsoftonline.com");
        context.setBrowserLauncher(new MSOpenTechExternalBrowserLauncher());
        final ListenableFuture<AuthenticationResult> future = context.acquireTokenInteractiveAsync(
                CommonTenant,
                resource,
                clientId,
                redirectUri.toString(),
                "login"
        );

        final AuthenticationResult result;
        try {
            result = future.get(10, TimeUnit.MINUTES);
        } catch (TimeoutException e) {
            throw new AuthorizationException("Failed to get authentication result within 10 minutes.");
        }

        logger.debug("Retrieved an authenticationResult, existing SWT library.");

        context.dispose();
        return result;
    }
}
