// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.pat;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.alm.auth.BaseAuthenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.oauth.Global;
import com.microsoft.alm.auth.oauth.OAuth2Authenticator;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.HttpClient;
import com.microsoft.alm.helpers.HttpClientImpl;
import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.secret.VsoTokenScope;
import com.microsoft.alm.storage.SecretStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Authenticator based on Personal Access Token
 *
 * This authenticator will attempt to reuse PATs found in store without regard to the scopes of the PAT.
 *
 * If the PAT does not have the correct scope, the only way is to reauth by either {@link #signOut(URI)} or {@link
 * PromptBehavior} ALWAYS.
 */
public class VstsPatAuthenticator extends BaseAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(VstsPatAuthenticator.class);

    private final static String TYPE = "PersonalAccessToken";

    private final VsoAzureAuthority vsoAzureAuthority;

    private final OAuth2Authenticator vstsOauthAuthenticator;

    private final SecretStore<Token> store;

    private final ObjectMapper objectMapper;

    /**
     * Create a Personal Access Token Authenticator backed by the OAuth2 app with {@code oauthClientId} and
     * {@code oauthClientRedirectUri}.
     *
     * The oauthTokenStore will be utilized to check if there is valid OAuth2 {@link TokenPair} available first
     *
     * @param oauthClientId
     *      registered OAuth2 client id
     * @param oauthClientRedirectUrl
     *      registered OAuth2 client redirect URI
     * @param oauthTokenStore
     *      A secret store that will be used to check for available OAuth2 TokenPair
     * @param store
     *      Store for personal access tokens
     */
    public VstsPatAuthenticator(final String oauthClientId, final String oauthClientRedirectUrl,
                                final SecretStore<TokenPair> oauthTokenStore,
                                final SecretStore<Token> store) {
        Debug.Assert(oauthClientId!= null, "oauthClientId cannot be null");
        Debug.Assert(oauthClientRedirectUrl!= null, "oauthClientRedirectUrl cannot be null");
        Debug.Assert(store != null, "store cannot be null");

        this.vstsOauthAuthenticator = OAuth2Authenticator.getAuthenticator(oauthClientId,
                oauthClientRedirectUrl, oauthTokenStore);
        this.vsoAzureAuthority = new VsoAzureAuthority();
        this.store = store;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Create a Personal Access Token Authenticator backed a particular {@link OAuth2Authenticator}
     *
     * @param oauth2Authenticator
     *      a fully materialized oauth2 authenticator
     * @param store
     *      Store for personal access tokens
     */
    public VstsPatAuthenticator(final OAuth2Authenticator oauth2Authenticator, final SecretStore<Token> store) {
        this(new VsoAzureAuthority(), oauth2Authenticator, store);
    }

    /* default */ VstsPatAuthenticator(final VsoAzureAuthority vsoAzureAuthority,
                                       final OAuth2Authenticator oauth2Authenticator,
                                        final SecretStore<Token> store) {
        //only those two fields are passed in from outside of this class
        Debug.Assert(oauth2Authenticator != null, "oauth2Authenticatorcannot be null");
        Debug.Assert(store != null, "store cannot be null");

        this.vsoAzureAuthority = vsoAzureAuthority;
        this.vstsOauthAuthenticator = oauth2Authenticator;
        this.store = store;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    protected SecretStore<Token> getStore() {
        return this.store;
    }

    @Override
    public String getAuthType() {
        return TYPE;
    }

    @Override
    public boolean isPersonalAccessTokenSupported() {
        return true;
    }

    @Override
    public Token getPersonalAccessToken(final VsoTokenScope tokenScope, final String patDisplayName,
                                        final PromptBehavior promptBehavior) {
        // Global PAT will be stored with URI key APP_VSSPS_VISUALSTUDIO as this key doesn't identify any account
        logger.debug("Retrieving global Personal Access Token.");
        return getToken(vstsOauthAuthenticator.APP_VSSPS_VISUALSTUDIO, true, tokenScope,
                patDisplayName, promptBehavior, null);
    }

    @Override
    public Token getPersonalAccessToken(final URI uri, final VsoTokenScope tokenScope, final String patDisplayName,
                                        final PromptBehavior promptBehavior) {
        logger.debug("Retrieving Personal Access Token for uri: {}", uri);
        return getToken(uri, false, tokenScope, patDisplayName, promptBehavior, null);
    }

    @Override
    public Token getPersonalAccessToken(final URI uri, final VsoTokenScope tokenScope, final String patDisplayName,
                                        final PromptBehavior promptBehavior, final TokenPair oauth2Token) {
        logger.debug("Retrieving Personal Access Token for uri: {}", uri);
        return getToken(uri, false, tokenScope, patDisplayName, promptBehavior, oauth2Token);
    }

    private Token getToken(final URI uri, final boolean isCreatingGlobalPat,
                           final VsoTokenScope tokenScope, final String patDisplayName,
                           final PromptBehavior promptBehavior, final TokenPair oauth2Token) {
        Debug.Assert(uri != null, "uri cannot be null");
        Debug.Assert(promptBehavior != null, "promptBehavior cannot be null");

        logger.info("Retrieving PersonalAccessToken for uri:{} with name:{}, and with scope:{}, prompt behavior: {}",
                uri, patDisplayName, tokenScope, promptBehavior.name());

        final String key = getKey(uri);
        Debug.Assert(key != null, "Failed to convert uri to key");

        final SecretRetriever<Token> secretRetriever = new SecretRetriever<Token>() {
            @Override
            protected boolean tryGetValidated(final Token token, final AtomicReference<Token> holder) {
                Debug.Assert(token != null, "Token is null");
                Debug.Assert(holder != null, "Holder is null");

                final URI validationEndpoint = URI.create(uri + "/_apis/connectionData");
                boolean valid = false;

                if (token.Value != null) {
                    final HttpClientImpl client = new HttpClientImpl(Global.getUserAgent());
                    token.contributeHeader(client.Headers);
                    try {
                        client.getGetResponseText(validationEndpoint);
                        valid = true;
                    } catch (IOException e) {
                        logger.debug("Validation failed with IOException.", e);
                    }
                }

                logger.debug("Personal Access Token is {}.", valid ? "valid" : "invalid.");
                return valid;
            }

            @Override
            protected Token doRetrieve() {
                final TokenPair tokenPair = (oauth2Token == null)
                        ? vstsOauthAuthenticator.getOAuth2TokenPair(uri, promptBehavior.AUTO)
                        : oauth2Token;

                if (tokenPair == null) {
                    // authentication failed, return null
                    logger.debug("Failed to get an OAuth2 token, cannot generate PersonalAccessToken.");
                    return null;
                }
                logger.debug("Got OAuth2 token, retrieving Personal Access Token with it.");

                final URI accountSpecificUri = createAccountSpecificUri(uri, tokenPair);
                final Token pat = vsoAzureAuthority.generatePersonalAccessToken(accountSpecificUri, tokenPair.AccessToken,
                        tokenScope, true, isCreatingGlobalPat, patDisplayName);

                return pat;
            }
        };

        return secretRetriever.retrieve(key, getStore(), promptBehavior);
    }

    private URI createAccountSpecificUri(final URI uri, final TokenPair tokenPair) {
        if (vstsOauthAuthenticator.APP_VSSPS_VISUALSTUDIO.equals(uri)) {
            logger.debug("Find an account level target url to generate Personal Access Token.");
            final HttpClientImpl client = new HttpClientImpl(Global.getUserAgent());
            tokenPair.AccessToken.contributeHeader(client.Headers);

            try {
                final String profileId = getProfileId(client);
                final String accountUri = getAccountUri(client, profileId);

                logger.debug("Found account: {}", accountUri);
                return URI.create(accountUri);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        // no need to translate any other uri
        return uri;
    }

    private String getProfileId(final HttpClient authenticatedClient) throws IOException {
        Debug.Assert(authenticatedClient != null, "authenticatedClient is null");

        final URI profileUri = URI.create("https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=1.0");
        final HttpURLConnection response;
        logger.debug("Getting user profile...");
        final String responseText = authenticatedClient.getGetResponseText(profileUri);

        final String id = parseIdFromJson(responseText);
        if (id != null) {
            logger.debug("Profile id: {}", id);
            return id;
        }

        throw new RuntimeException("Failed to get profile id.");
    }

    private static final Pattern ID_PATTERN = Pattern.compile(
            "\"id\"\\s*:\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE
    );

    static String parseIdFromJson(final String json) {
        String result = null;

        final Matcher matcher = ID_PATTERN.matcher(json);
        if (matcher.find()) {
            result = matcher.group(1);
        }

        return result;
    }

    private String getAccountUri(final HttpClient authenticatedClient, final String profileId) throws IOException {
        Debug.Assert(authenticatedClient != null, "authenticatedClient is null");
        Debug.Assert(profileId != null, "profileId is null");

        final String accountApiUrlFormat = "https://app.vssps.visualstudio.com/_apis/Accounts?memberid=%s&api-version=1.0";
        final URI accountApiUrl = URI.create(String.format(accountApiUrlFormat, profileId));

        final String vstsAccountUrlFormat = "https://%s.visualstudio.com/";

        logger.debug("Account API URL: {}", accountApiUrl);

        final String content = authenticatedClient.getGetResponseText(accountApiUrl);

        if (content != null) {
            final AccountList accountList = this.objectMapper.readValue(content, AccountList.class);
            if (accountList != null && accountList.value != null) {
                for (final Account account : accountList.value) {
                    if (account.accountStatus != null && account.accountUri != null) {
                        return String.format(vstsAccountUrlFormat, account.accountName);
                    }
                }
            }
        }

        throw new RuntimeException("Could not find any accounts.");
    }

    /**
     * "Forget" the global PAT, also remove the oauth token to force sign in again
     *
     * @return {@code true} if global PAT and the OAuth2 token used to generate this PAT are both forgotten
     */
    @Override
    public boolean signOut() {
        return this.signOut(vstsOauthAuthenticator.APP_VSSPS_VISUALSTUDIO);
    }

    @Override
    public boolean signOut(final URI uri) {
        logger.info("Signing out from uri: {}", uri);
        Debug.Assert(uri != null, "uri cannot be null");

        return super.signOut(uri)
                && vstsOauthAuthenticator.signOut();
    }

    /**
     * @deprecated Global PAT is going away soon
     *
     * Since global PAT suppose to work across accounts, we can associate the global PAT to a particular account
     * and everything should still work.
     *
     * @param uri
     *      Target account uri
     *
     * @return {@code true} if there is a global PAT and we successfully associated it with the target uri
     *         {@code false} otherwise
     */
    public boolean assignGlobalPatTo(final URI uri) {
        Debug.Assert(uri != null, "uri cannot be null");
        logger.debug("Assigning the global PAT to uri: {}", uri);

        final String globalKey = getKey(vstsOauthAuthenticator.APP_VSSPS_VISUALSTUDIO);
        final Token token = getStore().get(globalKey);
        if (token != null) {
            assign(uri, token);
            logger.debug("Global PAT transferred to uri: {}", uri);
            return true;
        } else {
            logger.debug("Could not find global PAT.");
        }

        return false;
    }

    private void assign(final URI uri, final Token token) {
        final String key = getKey(uri);
        getStore().add(key, token);
    }

    /**
     * Simple data-binding classes for parsing VSTS Accounts from JSON
     *
     * This class is used in order to avoid a full dependency on VSTS REST Http client
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AccountList {
        public int count;
        public List<Account> value;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Account {
        public UUID accountId;
        public URI accountUri;
        public String accountName;
        public String organizationName;
        public String accountType;
        public UUID accountOwner;
        public String accountStatus;
    }
}
