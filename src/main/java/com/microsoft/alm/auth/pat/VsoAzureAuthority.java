// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.pat;

import com.microsoft.alm.auth.oauth.AzureAuthority;
import com.microsoft.alm.auth.oauth.Global;
import com.microsoft.alm.auth.secret.Token;
import com.microsoft.alm.auth.secret.TokenType;
import com.microsoft.alm.auth.secret.VsoTokenScope;
import com.microsoft.alm.helpers.Action;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.Guid;
import com.microsoft.alm.helpers.HttpClient;
import com.microsoft.alm.helpers.StringContent;
import com.microsoft.alm.helpers.StringHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class VsoAzureAuthority extends AzureAuthority {

    private static final Logger logger = LoggerFactory.getLogger(VsoAzureAuthority.class);

    /**
     * The maximum wait time for a network request before timing out
     */
    public static final int RequestTimeout = 15 * 1000; // 15 second limit

    private final static String ALL_ACCOUNTS = "all_accounts";

    /**
     * Generates a personal access token for use with Visual Studio Online.
     *
     * @param targetUri           The uniform resource indicator of the resource access tokens are being requested for.
     * @param accessToken
     * @param tokenScope
     * @param requireCompactToken
     * @return
     */
    public Token generatePersonalAccessToken(final URI targetUri, final Token accessToken,
                                             final VsoTokenScope tokenScope, final boolean requireCompactToken,
                                             final boolean shouldCreateGlobalToken, final String displayName) {
        final String TokenAuthHost = "app.vssps.visualstudio.com";
        final String SessionTokenUrl = "https://" + TokenAuthHost + "/_apis/token/sessiontokens?api-version=1.0";
        final String CompactTokenUrl = SessionTokenUrl + "&tokentype=compact";

        Debug.Assert(targetUri != null, "The targetUri parameter is null");
        Debug.Assert(accessToken != null && !StringHelper.isNullOrWhiteSpace(accessToken.Value) && (accessToken.Type == TokenType.Access || accessToken.Type == TokenType.Federated), "The accessToken parameter is null or invalid");
        Debug.Assert(tokenScope != null, "The tokenScope parameter is invalid");

        logger.debug("VsoAzureAuthority::generatePersonalAccessToken");

        try {
            // TODO: 449524: create a `HttpClient` with a minimum number of redirects, default creds, and a reasonable timeout (access token generation seems to hang occasionally)
            final HttpClient client = new HttpClient(Global.getUserAgent());
            logger.debug("   using token to acquire personal access token");
            accessToken.contributeHeader(client.Headers);

            if (shouldCreateGlobalToken || populateTokenTargetId(targetUri, accessToken)) {
                final URI requestUrl = URI.create(requireCompactToken ? CompactTokenUrl : SessionTokenUrl);

                final StringContent content = getAccessTokenRequestBody(accessToken, tokenScope,
                        shouldCreateGlobalToken, displayName);

                final HttpURLConnection response = client.post(requestUrl, content);
                if (response.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    final String responseText = HttpClient.readToString(response);

                    final Token token = parsePersonalAccessTokenFromJson(responseText);
                    if (token != null) {
                        logger.debug("   personal access token acquisition succeeded.");
                    }
                    return token;
                }
            }
        } catch (IOException e) {
            throw new Error(e);
        }
        return null;
    }

    public boolean populateTokenTargetId(final URI targetUri, final Token accessToken) {
        Debug.Assert(targetUri != null && targetUri.isAbsolute(), "The targetUri parameter is null or invalid");
        Debug.Assert(accessToken != null && !StringHelper.isNullOrWhiteSpace(accessToken.Value)
                && (accessToken.Type == TokenType.Access || accessToken.Type == TokenType.Federated),
                "The accessToken parameter is null or invalid");

        logger.debug("VsoAzureAuthority::populateTokenTargetId");

        String resultId = null;
        try {
            // create an request to the VSO deployment data end-point
            final HttpURLConnection request = createConnectionDataRequest(targetUri, accessToken);

            // send the request and wait for the response
            final String content = HttpClient.readToString(request);

            resultId = parseInstanceIdFromJson(content);
        } catch (final IOException e) {
            logger.debug("   server returned " + e.getMessage());
        }

        final AtomicReference<UUID> instanceId = new AtomicReference<UUID>();
        if (Guid.tryParse(resultId, instanceId)) {
            logger.debug("   target identity is " + resultId);
            accessToken.setTargetIdentity(instanceId.get());

            return true;
        }

        return false;
    }

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\"token\"\\s*:\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE
    );

    static Token parsePersonalAccessTokenFromJson(final String json) {
        Token token = null;
        if (!StringHelper.isNullOrWhiteSpace(json)) {
            // find the 'token : <value>' portion of the result content, if any
            final Matcher matcher = TOKEN_PATTERN.matcher(json);
            if (matcher.find()) {
                final String tokenValue = matcher.group(1);
                token = new Token(tokenValue, TokenType.Personal);
            }
        }
        return token;
    }

    private static final Pattern INSTANCE_ID_PATTERN = Pattern.compile(
            "\"instanceId\"\\s*:\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE
    );

    static String parseInstanceIdFromJson(final String json) {
        String result = null;

        final Matcher matcher = INSTANCE_ID_PATTERN.matcher(json);
        if (matcher.find()) {
            result = matcher.group(1);
        }

        return result;
    }

    private StringContent getAccessTokenRequestBody(final Token accessToken, final VsoTokenScope tokenScope,
                                                    final boolean shouldCreateGlobalToken, final String displayName) {
        final String ContentJsonFormat = "{ \"scope\" : \"%1$s\", \"targetAccounts\" : [\"%2$s\"], \"displayName\" : \"%3$s\" }";

        Debug.Assert(accessToken != null && (accessToken.Type == TokenType.Access || accessToken.Type == TokenType.Federated), "The accessToken parameter is null or invalid");
        Debug.Assert(tokenScope != null, "The tokenScope parameter is null");

        final String targetIdentity = shouldCreateGlobalToken ? ALL_ACCOUNTS : accessToken.getTargetIdentity().toString();
        logger.debug("   creating access token scoped to '" + tokenScope + "' for '" + targetIdentity + "'");

        final String jsonContent = String.format(ContentJsonFormat, tokenScope, targetIdentity, displayName);
        final StringContent content = StringContent.createJson(jsonContent);
        return content;
    }


    private HttpURLConnection createConnectionDataRequest(final URI targetUri, final Token token) throws IOException {
        Debug.Assert(targetUri != null && targetUri.isAbsolute(), "The targetUri parameter is null or invalid");
        Debug.Assert(token != null && (token.Type == TokenType.Access || token.Type == TokenType.Federated), "The token parameter is null or invalid");

        logger.debug("VsoAzureAuthority::createConnectionDataRequest");

        final HttpClient client = new HttpClient(Global.getUserAgent());

        // create an request to the VSO deployment data end-point
        final URI requestUri = createConnectionDataUri(targetUri);

        logger.debug("   validating token");
        token.contributeHeader(client.Headers);

        final HttpURLConnection result = client.get(requestUri, new Action<HttpURLConnection>() {
            @Override
            public void call(final HttpURLConnection conn) {
                conn.setConnectTimeout(RequestTimeout);
            }
        });
        return result;
    }

    private URI createConnectionDataUri(final URI targetUri) {
        final String VsoValidationUrlFormat = "https://%1$s/_apis/connectiondata";

        Debug.Assert(targetUri != null & targetUri.isAbsolute(), "The targetUri parameter is null or invalid");

        // create a url to the connection data end-point, it's deployment level and "always on".
        final String validationUrl = String.format(VsoValidationUrlFormat, targetUri.getHost());

        final URI result = URI.create(validationUrl);
        return result;
    }
}
