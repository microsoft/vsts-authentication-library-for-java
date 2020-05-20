// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.common.helpers.*;
import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.oauth2.useragent.AuthorizationResponse;
import com.microsoft.alm.oauth2.useragent.UserAgent;
import com.microsoft.alm.oauth2.useragent.UserAgentImpl;
import com.microsoft.alm.common.secret.Token;
import com.microsoft.alm.common.secret.TokenPair;
import com.microsoft.alm.common.secret.TokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

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

    /**
     * AzureAuthority with common tenant
     */
    public static final AzureAuthority DefaultAzureAuthority = new AzureAuthority();

    private static final String VSTS_BASE_DOMAIN = "visualstudio.com";
    private static final String VSTS_RESOURCE_TENANT_HEADER = "X-VSS-ResourceTenant";

    private final UserAgent userAgent;
    private final AzureDeviceFlow azureDeviceFlow;

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
        this(authorityHostUrl, new UserAgentImpl(), new AzureDeviceFlow());
    }

    AzureAuthority(final String authorityHostUrl, final UserAgent userAgent, final AzureDeviceFlow azureDeviceFlow) {
        Debug.Assert(UriHelper.isWellFormedUriString(authorityHostUrl), "The authorityHostUrl parameter is invalid.");
        Debug.Assert(userAgent != null, "The userAgent parameter is null.");

        this.authorityHostUrl = authorityHostUrl;
        this.userAgent = userAgent;
        this.azureDeviceFlow = azureDeviceFlow;
    }

    static URI createAuthorizationEndpointUri(final String authorityHostUrl, final String resource, final String clientId,
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

    static URI createTokenEndpointUri(final String authorityHostUrl) {
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

    static StringContent createTokenRequest(final String resource, final String clientId, final String authorizationCode,
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

    static StringContent createTokenRequestByRefreshToken(final String resource, final String clientId,
                                                            final Token refreshToken) {

        final QueryString qs = new QueryString();

        qs.put(OAuthParameter.RESOURCE, resource);
        qs.put(OAuthParameter.CLIENT_ID, clientId);
        qs.put(OAuthParameter.GRANT_TYPE, OAuthParameter.REFRESH_TOKEN);
        qs.put(OAuthParameter.REFRESH_TOKEN, refreshToken.Value);

        final StringContent result = StringContent.createUrlEncoded(qs);
        return result;
    }

    /**
     * Determines if there's the targetUri represents a Visual Studio Team Services account
     * backed by Azure Active Directory (AAD).
     *
     * @param targetUri the resource which the authority protects.
     * @return the AAD tenant ID if applicable; {@code null} otherwise.
     */
    public static UUID detectTenantId(final URI targetUri) throws IOException {
        final AtomicReference<UUID> tenantId = new AtomicReference<UUID>(Guid.Empty);

        if (StringHelper.endsWithIgnoreCase(targetUri.getHost(), VSTS_BASE_DOMAIN) ||
                UriHelper.isAzureHost(targetUri)) {
            final HttpClient client = Global.getHttpClientFactory().createHttpClient();
            final String tenant = client.getHeaderField(targetUri, VSTS_RESOURCE_TENANT_HEADER);

            if (!StringHelper.isNullOrWhiteSpace(tenant)) {
                if (Guid.tryParse(tenant, tenantId)) {
                    if (!Guid.Empty.equals(tenantId.get())) {
                        return tenantId.get();
                    }
                }
            }
        }

        return null;
    }

    private TokenPair doAcquireToken(final URI tokenEndpoint, final StringContent requestContent) throws IOException {
        final HttpClient client = Global.getHttpClientFactory().createHttpClient();

        final String responseContent = client.getPostResponseText(tokenEndpoint, requestContent);
        final TokenPair tokenPair = new TokenPair(responseContent);

        return tokenPair;
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
     * @throws AuthorizationException if unable to authenticate and authorize the request
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

        try {
            final URI tokenEndpoint = createTokenEndpointUri(authorityHostUrl);
            final StringContent requestContent = createTokenRequest(resource, clientId, authorizationCode, redirectUri, correlationId);

            tokens = doAcquireToken(tokenEndpoint, requestContent);
            logger.debug("   token acquisition succeeded.");

        } catch (final IOException e) {
            // TODO: 449248: silently catching the exception here seems horribly wrong
            logger.debug("   token acquisition failed.");
            logger.debug("   IOException: {}", e);
        }
        return tokens;
    }

    /**
     * Acquires an access token from the authority using a previously acquired refresh token.
     *
     * @param clientId     Identifier of the client requesting the token.
     * @param resource     Identifier of the target resource that is the recipient of the requested token.
     * @param refreshToken The {@link Token} of type {@link TokenType#Refresh}.
     * @return If successful, a {@link TokenPair}; otherwise null.
     */
    public TokenPair acquireTokenByRefreshToken(final String clientId, final String resource,
                                                final Token refreshToken) {
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(clientId), "The clientId parameter is null or empty");
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(resource), "The resource parameter is null or empty");
        Debug.Assert(refreshToken != null, "The refreshToken parameter is null");

        logger.debug("AzureAuthority::acquireTokenByRefreshToken");

        final URI tokenEndpoint = createTokenEndpointUri(authorityHostUrl);
        final StringContent requestContent = createTokenRequestByRefreshToken(resource, clientId, refreshToken);

        try {
            final TokenPair tokenPair = doAcquireToken(tokenEndpoint, requestContent);
            return tokenPair;
        } catch (IOException e) {
            // TODO: 449248: silently catching the exception here seems horribly wrong - again
            logger.debug("   token acquisition failed.");
            logger.debug("   IOException: {}", e);
        }

        return null;
    }

    public TokenPair acquireToken(final String clientId, final String resource, final URI redirectUri,
                                  final Action<DeviceFlowResponse> callback) throws AuthorizationException {
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(clientId), "The clientId parameter is null or empty");
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(resource), "The resource parameter is null or empty");
        Debug.Assert(redirectUri != null, "The redirectUri parameter is null");
        Debug.Assert(callback != null, "The callback parameter is null");

        logger.debug("AzureAuthority::acquireToken");

        azureDeviceFlow.setResource(resource);
        azureDeviceFlow.setRedirectUri(redirectUri.toString());

        final URI deviceEndpoint = URI.create(authorityHostUrl + "/oauth2/devicecode");
        final DeviceFlowResponse response = azureDeviceFlow.requestAuthorization(deviceEndpoint, clientId, null);

        callback.call(response);

        final URI tokenEndpoint = createTokenEndpointUri(authorityHostUrl);
        final TokenPair tokens = azureDeviceFlow.requestToken(tokenEndpoint, clientId, response);

        logger.debug("   token acquisition succeeded.");
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

}
