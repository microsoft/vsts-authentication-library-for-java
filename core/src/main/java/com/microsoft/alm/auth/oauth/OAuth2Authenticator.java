// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.auth.BaseAuthenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.oauth.helper.AzureAuthorityProvider;
import com.microsoft.alm.auth.oauth.helper.SwtJarLoader;
import com.microsoft.alm.helpers.Action;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.HttpClient;
import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.oauth2.useragent.Provider;
import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.InsecureInMemoryStore;
import com.microsoft.alm.storage.SecretStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static com.microsoft.alm.helpers.LoggingHelper.logError;

public class OAuth2Authenticator extends BaseAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Authenticator.class);

    public final static String POPUP_QUERY_PARAM = "display=popup";

    public final static URI APP_VSSPS_VISUALSTUDIO = URI.create("https://app.vssps.visualstudio.com");
    public final static String MANAGEMENT_CORE_RESOURCE = "https://management.core.windows.net/";
    public final static String VALIDATION_ENDPOINT = APP_VSSPS_VISUALSTUDIO + "/_apis/connectionData";
    public static final String VSTS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798";

    private final static String TYPE = "OAuth2";

    // oauth2-useragent should expose this property as public property, it shouldn't be exposed from here,
    // hence "private" modifier
    private static final String USER_AGENT_PROVIDER_PROPERTY_NAME = "userAgentProvider";

    private final String resource;
    private final String clientId;
    private final URI redirectUri;

    private final SecretStore<TokenPair> store;

    private final OAuth2UseragentValidator oAuth2UseragentValidator;

    private final Action<DeviceFlowResponse> deviceFlowCallback;

    private AzureAuthorityProvider azureAuthorityProvider = new AzureAuthorityProvider();

    /**
     * Get an OAuth2 authenticator
     *
     * @param clientId
     *      Registered OAuth2 client id
     * @param redirectUrl
     *      Callback url for the registered client
     * @param store
     *      SecretStore to read and save access token to
     *
     * @return an OAuth2Authenticator
     */
    public static OAuth2Authenticator getAuthenticator(final String clientId, final String redirectUrl,
                                                       final SecretStore<TokenPair> store) {
        logger.debug("Authenticator manages resource: {}", MANAGEMENT_CORE_RESOURCE);

        return new OAuth2AuthenticatorBuilder()
                .manage(MANAGEMENT_CORE_RESOURCE)
                .withClientId(clientId)
                .redirectTo(redirectUrl)
                .backedBy(store)
                .build();
    }

    /**
     * Get an OAuth2 authenticator
     *
     * @param clientId
     *      Registered OAuth2 client id
     * @param redirectUrl
     *      Callback url for the registered client
     * @param store
     *      SecretStore to read and save access token to
     * @param deviceFlowCallback
     *      an implementation of {@link Action} to invoke when participating
     *      in OAuth 2.0 Device Flow, providing the end-user with a URI and a code to use for
     *      authenticating in an external web browser
     *
     * @return an OAuth2Authenticator
     */
    public static OAuth2Authenticator getAuthenticator(final String clientId, final String redirectUrl,
                                                       final SecretStore<TokenPair> store, final Action<DeviceFlowResponse> deviceFlowCallback) {
        logger.debug("Authenticator manages resource: {}", MANAGEMENT_CORE_RESOURCE);

        return new OAuth2AuthenticatorBuilder()
                .manage(MANAGEMENT_CORE_RESOURCE)
                .withClientId(clientId)
                .redirectTo(redirectUrl)
                .backedBy(store)
                .withDeviceFlowCallback(deviceFlowCallback)
                .build();
    }

    /*default*/ OAuth2Authenticator(final String resource, final String clientId, final URI redirectUri,
                        final SecretStore<TokenPair> store, final OAuth2UseragentValidator oAuth2UseragentValidator,
                        final Action<DeviceFlowResponse> deviceFlowCallback) {
        Debug.Assert(resource != null, "resource cannot be null");
        Debug.Assert(clientId != null, "clientId cannot be null");
        Debug.Assert(redirectUri != null, "redirectUri cannot be null");

        this.resource = resource;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.oAuth2UseragentValidator = oAuth2UseragentValidator;
        this.deviceFlowCallback = deviceFlowCallback;

        logger.debug("Using default SecretStore? {}", store == null);
        this.store = store == null ? new InsecureInMemoryStore<TokenPair>() : store;
    }

    @Override
    public String getAuthType() {
        return this.TYPE;
    }

    @Override
    protected SecretStore<TokenPair> getStore() {
        return this.store;
    }

    @Override
    public boolean isOAuth2TokenSupported() {
        return true;
    }

    @Override
    public TokenPair getOAuth2TokenPair() {
        return getOAuth2TokenPair(APP_VSSPS_VISUALSTUDIO, PromptBehavior.AUTO);
    }

    @Override
    public TokenPair getOAuth2TokenPair(final PromptBehavior promptBehavior) {
        return getOAuth2TokenPair(APP_VSSPS_VISUALSTUDIO, promptBehavior);
    }

    @Override
    public TokenPair getOAuth2TokenPair(final URI uri, final PromptBehavior promptBehavior) {
        Debug.Assert(promptBehavior != null, "getOAuth2TokenPair promptBehavior cannot be null");
        Debug.Assert(uri != null, "getOAuth2TokenPair uri cannot be null");

        logger.debug("Retrieving OAuth2 TokenPair with prompt behavior: {}", promptBehavior.name());

        final String key = getKey(APP_VSSPS_VISUALSTUDIO);

        final SecretRetriever<TokenPair> secretRetriever = new SecretRetriever<TokenPair>() {

            private boolean validateAccessToken(final Token accessToken, final URI validationEndpoint) {
                final HttpClient client = new HttpClient(Global.getUserAgent());
                accessToken.contributeHeader(client.Headers);
                try {
                    final HttpURLConnection response = client.get(validationEndpoint);

                    return response.getResponseCode() == HttpURLConnection.HTTP_OK;
                } catch (IOException e) {
                    logger.debug("Validation failed with IOException.", e);
                }

                return false;
            }

            @Override
            protected boolean tryGetValidated(final TokenPair tokenPair, final AtomicReference<TokenPair> holder) {
                Debug.Assert(tokenPair != null, "TokenPair is null");
                Debug.Assert(holder != null, "Holder is null");

                final URI validationEndpoint = URI.create(VALIDATION_ENDPOINT);
                boolean valid = false;

                if (tokenPair.AccessToken != null) {
                    logger.debug("Validating stored OAuth2 Access Token...");
                    valid = validateAccessToken(tokenPair.AccessToken, validationEndpoint);
                }

                if (!valid && tokenPair.RefreshToken != null) {
                    logger.debug("OAuth2 Access Token is not valid, and we have a refresh token, try refreshing...");

                    final TokenPair renewedTokenPair =
                            getAzureAuthority(uri).acquireTokenByRefreshToken(clientId, resource, tokenPair.RefreshToken);

                    // Today after we refresh oauth2 token with the refresh token, we are only getting back an
                    // Access Token -- the refresh token is null.  Although we could use this Access Token for another
                    // hour, this contradicts with the assumption of this library (Both AccessToken and
                    // RefreshToken fields of the TokenPair class are non-null).
                    // TODO: investigate next sprint, after 7/28
                    if (renewedTokenPair != null
                            && renewedTokenPair.AccessToken.Value != null
                            && renewedTokenPair.RefreshToken.Value != null) {
                        logger.debug("OAuth2 Access Token refreshed successfully.");
                        valid = true;
                        holder.set(renewedTokenPair);
                    }
                }

                logger.debug("OAuth2 Access Token is {}.", valid ? "valid" : "invalid.");
                return valid;
            }

            @Override
            protected TokenPair doRetrieve() {
                logger.debug("Ready to launch browser flow to retrieve oauth2 token.");

                final AtomicReference<File> swtRuntime = new AtomicReference<File>();

                final String defaultProviderName
                        = System.getProperty(USER_AGENT_PROVIDER_PROPERTY_NAME, Provider.JAVA_FX.getClassName());

                final boolean favorSwtBrowser
                        = defaultProviderName.equals(Provider.STANDARD_WIDGET_TOOLKIT.getClassName());

                final boolean favorDeviceFlow = defaultProviderName.equalsIgnoreCase("none");

                if (favorSwtBrowser) {
                    logger.debug("Prefer SWT Browser, download SWT Runtime if it is not available.");
                    if (oAuth2UseragentValidator.isOnlyMissingRuntimeFromSwtProvider()) {
                        SwtJarLoader.tryGetSwtJar(swtRuntime);
                    }
                }

                if (!favorDeviceFlow && oAuth2UseragentValidator.isOAuth2ProviderAvailable()
                        || (oAuth2UseragentValidator.isOnlyMissingRuntimeFromSwtProvider()
                            && SwtJarLoader.tryGetSwtJar(swtRuntime))) {
                    try {
                        logger.info("Using oauth2-useragent providers to retrieve AAD token.");
                        return getAzureAuthority(uri).acquireToken(clientId, resource, redirectUri, POPUP_QUERY_PARAM);
                    } catch (final AuthorizationException e) {
                        logError(logger, "Failed to launch oauth2-useragent.", e);
                        // unless we failed with unknown reasons (such as failed to load javafx) we probably should
                        // just return null
                        if (!"unknown_error".equalsIgnoreCase(e.getCode())) {
                            // This error code isn't exposed as a value, so just hardcode this string
                            return null;
                        }
                    }
                }

                // Fallback to Device Flow if there's a callback and the oauth2-useragent couldn't launch the
                // browser properly
                if (deviceFlowCallback != null) {
                    logger.info("Fallback to Device Flow.");
                    try {
                        return getAzureAuthority(uri).acquireToken(clientId, resource, redirectUri, deviceFlowCallback);
                    } catch (final AuthorizationException e) {
                        logError(logger, "Failed to use the Device Flow authenticator.", e);
                    }
                }

                return null;
            }
        };

        return secretRetriever.retrieve(key, getStore(), promptBehavior);
    }

    public boolean signOut() {
        return super.signOut(APP_VSSPS_VISUALSTUDIO);
    }

    // For unit test
    /*default*/ void setAzureAuthorityProvider(final AzureAuthorityProvider azureAuthorityProvider) {
        this.azureAuthorityProvider = azureAuthorityProvider;
    }

    private AzureAuthority getAzureAuthority(final URI uri) {
        return this.azureAuthorityProvider.getAzureAuthority(uri);
    }

    public static class OAuth2AuthenticatorBuilder {
        private String resource;
        private String clientId;
        private URI redirectUri;
        private SecretStore store;
        private String tenantId = AzureAuthority.CommonTenant;
        private Action<DeviceFlowResponse> deviceFlowCallback;

        public OAuth2AuthenticatorBuilder manage(final String resource) {
            Debug.Assert(resource != null, "resource cannot be null");
            this.resource = resource;
            return this;
        }

        public OAuth2AuthenticatorBuilder withClientId(final UUID clientId) {
            return this.withClientId(clientId.toString());
        }

        public OAuth2AuthenticatorBuilder withClientId(final String clientId) {
            Debug.Assert(clientId != null, "clientId cannot be null");
            this.clientId = clientId;
            return this;
        }

        public OAuth2AuthenticatorBuilder redirectTo(final URI redirectUri) {
            Debug.Assert(redirectUri != null, "redirectUri cannot be null");
            this.redirectUri = redirectUri;
            return this;
        }

        public OAuth2AuthenticatorBuilder redirectTo(final String redirectUri) {
            return this.redirectTo(URI.create(redirectUri));
        }

        public OAuth2AuthenticatorBuilder backedBy(final SecretStore store) {
            Debug.Assert(store != null, "store cannot be null");
            this.store = store;
            return this;
        }

        public OAuth2AuthenticatorBuilder withDeviceFlowCallback(final Action<DeviceFlowResponse> deviceFlowCallback) {
            this.deviceFlowCallback = deviceFlowCallback;
            return this;
        }

        public OAuth2Authenticator build() {
            if (this.clientId == null) {
                throw new IllegalStateException("ClientId not set");
            }

            if (this.resource == null) {
                throw new IllegalStateException("resource not set");
            }

            if (this.redirectUri == null) {
                throw new IllegalStateException("redirectUri not set");
            }

            final OAuth2UseragentValidator oAuth2UseragentValidator = new OAuth2UseragentValidator();

            return new OAuth2Authenticator(this.resource, this.clientId, this.redirectUri, this.store,
                    oAuth2UseragentValidator, this.deviceFlowCallback);
        }
    }
}
