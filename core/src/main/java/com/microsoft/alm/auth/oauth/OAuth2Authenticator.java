// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.auth.BaseAuthenticator;
import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.helpers.Action;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.InsecureInMemoryStore;
import com.microsoft.alm.storage.SecretStore;
import com.microsoftopentechnologies.auth.AuthenticationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.UUID;

import static com.microsoft.alm.helpers.LoggingHelper.logError;

public class OAuth2Authenticator extends BaseAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Authenticator.class);

    public final static String POPUP_QUERY_PARAM = "display=popup";

    public final static URI APP_VSSPS_VISUALSTUDIO = URI.create("https://app.vssps.visualstudio.com");
    public final static String MANAGEMENT_CORE_RESOURCE = "https://management.core.windows.net/";

    private final static String TYPE = "OAuth2";

    private final String resource;
    private final String clientId;
    private final URI redirectUri;

    private final SecretStore<TokenPair> store;

    private final AzureAuthority azureAuthority;

    private final OAuth2UseragentValidator oAuth2UseragentValidator;

    private final Action<DeviceFlowResponse> deviceFlowCallback;

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
     *      an implementation of {@link Action<DeviceFlowResponse>} to invoke when participating
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

    /**
     * Private constructor so we are guaranteed resource is https://management.core.windows.net.
     *
     * If user wish to construct an authenticator that can work with other protected resource, use
     * {@link com.microsoft.alm.auth.oauth.OAuth2Authenticator.OAuth2AuthenticatorBuilder}
     *
     */
    private OAuth2Authenticator(final String resource, final String clientId, final URI redirectUri,
                               final SecretStore<TokenPair> store, final Action<DeviceFlowResponse> deviceFlowCallback) {
        this(resource, clientId, redirectUri, store, new AzureAuthority(), new OAuth2UseragentValidator(), deviceFlowCallback);
    }

    /*default*/ OAuth2Authenticator(final String resource, final String clientId, final URI redirectUri,
                        final SecretStore<TokenPair> store, final AzureAuthority azureAuthority,
                        final OAuth2UseragentValidator oAuth2UseragentValidator, final Action<DeviceFlowResponse> deviceFlowCallback) {
        Debug.Assert(resource != null, "resource cannot be null");
        Debug.Assert(clientId != null, "clientId cannot be null");
        Debug.Assert(redirectUri != null, "redirectUri cannot be null");

        this.resource = resource;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.azureAuthority = azureAuthority;
        this.oAuth2UseragentValidator = oAuth2UseragentValidator;
        this.deviceFlowCallback = deviceFlowCallback;

        logger.debug("Using default SecretStore? {}", store == null);
        this.store = store == null ? new InsecureInMemoryStore<TokenPair>() : store;
    }

    private AzureAuthority getAzureAuthority() {
        return azureAuthority;
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
        return getOAuth2TokenPair(PromptBehavior.AUTO);
    }

    @Override
    public TokenPair getOAuth2TokenPair(final PromptBehavior promptBehavior) {
        Debug.Assert(promptBehavior != null, "getOAuth2TokenPair promptBehavior cannot be null");

        logger.debug("Retrieving OAuth2 TokenPair with prompt behavior: {}", promptBehavior.name());

        final String key = getKey(APP_VSSPS_VISUALSTUDIO);

        SecretRetriever secretRetriever = new SecretRetriever() {
            @Override
            protected TokenPair doRetrieve() {
                logger.debug("Ready to launch browser flow to retrieve oauth2 token.");

                final boolean userExplicitlyBlocksJavaFX
                        = "false".equalsIgnoreCase(System.getProperty("useJavaFxAuthLibrary"));

                if (oAuth2UseragentValidator.oauth2UserAgentAvailable() && !userExplicitlyBlocksJavaFX) {
                    try {
                        logger.info("Using oauth2-useragent providers to retrieve AAD token.");
                        return getAzureAuthority().acquireToken(clientId, resource, redirectUri, POPUP_QUERY_PARAM);
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

                // Always fallback to SWT browser if we failed to launch oauth2-useragent unexpectedly
                try {
                    logger.info("Fallback to MSOpenTech's AAD providers to retrieve AAD token.");

                    final AuthenticationResult result
                            = getAzureAuthority().acquireAuthenticationResult(clientId, resource, redirectUri);

                    if (result == null) {
                        logger.info("Failed to get an accessToken from MSOpenTech's AAD provider.");
                        return null;
                    }

                    return new TokenPair(result.getAccessToken(), result.getRefreshToken());
                } catch (Exception e) {
                    logError(logger, "Failed to use the SWT-based authenticator.", e);
                }

                // Fallback to Device Flow if there's a callback and the SWT-based authenticator failed
                if (deviceFlowCallback != null) {
                    try {
                        return getAzureAuthority().acquireToken(clientId, resource, deviceFlowCallback);
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

    public static class OAuth2AuthenticatorBuilder {
        private String resource;
        private String clientId;
        private URI redirectUri;
        private SecretStore store;
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

            return new OAuth2Authenticator(this.resource, this.clientId, this.redirectUri, this.store, this.deviceFlowCallback);
        }
    }
}
