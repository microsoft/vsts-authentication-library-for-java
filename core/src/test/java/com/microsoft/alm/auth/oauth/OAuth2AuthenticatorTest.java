// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.auth.oauth.helper.AzureAuthorityProvider;
import com.microsoft.alm.helpers.Action;
import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.SecretStore;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuth2AuthenticatorTest {

    private OAuth2Authenticator underTest;

    private SecretStore<TokenPair> mockStore;

    private AzureAuthority mockAzureAuthority;

    private AzureAuthorityProvider mockAzureAuthorityProvider;

    private OAuth2UseragentValidator mockOAuth2UseragentValidator;

    private Action<DeviceFlowResponse> testCallback;

    private final UUID clientId = UUID.randomUUID();

    private final URI TEST_REDIRECT_URI = URI.create("https://redirect.test");
    private final String TEST_RESOURCE = "test_resource";

    @Before
    public void setUp() throws Exception {
        mockStore = mock(SecretStore.class);
        mockAzureAuthority = mock(AzureAuthority.class);
        mockAzureAuthorityProvider = mock(AzureAuthorityProvider.class);
        mockOAuth2UseragentValidator = mock(OAuth2UseragentValidator.class);
        testCallback = new Action<DeviceFlowResponse>() {
            @Override
            public void call(final DeviceFlowResponse deviceFlowResponse) {
                // do nothing on purpose
            }
        };

        when(mockOAuth2UseragentValidator.isOnlyMissingRuntimeFromSwtProvider()).thenReturn(false);
        when(mockAzureAuthorityProvider.getAzureAuthority(any(URI.class))).thenReturn(mockAzureAuthority);

        underTest = new OAuth2Authenticator(TEST_RESOURCE,
                clientId.toString(),
                TEST_REDIRECT_URI,
                mockStore,
                mockOAuth2UseragentValidator,
                testCallback);

        underTest.setAzureAuthorityProvider(mockAzureAuthorityProvider);
    }

    @Test
    public void getTokenByAcquireToken_if_oauth2_useragent_available()
                throws URISyntaxException, AuthorizationException {
        when(mockOAuth2UseragentValidator.isOAuth2ProviderAvailable()).thenReturn(true);
        when(mockAzureAuthority.acquireToken(clientId.toString(), TEST_RESOURCE,
                TEST_REDIRECT_URI, underTest.POPUP_QUERY_PARAM))
                .thenReturn(new TokenPair("access", "refresh"));

        TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals("access", token.AccessToken.Value);
        assertEquals("refresh", token.RefreshToken.Value);

    }

    @Test
    public void getTokenByAcquireAuthenticationResult_if_neither_browser_is_available()
            throws URISyntaxException, InterruptedException, ExecutionException, IOException, AuthorizationException {
        when(mockOAuth2UseragentValidator.isOAuth2ProviderAvailable()).thenReturn(false);
        when(mockAzureAuthority.acquireToken(clientId.toString(), TEST_RESOURCE, TEST_REDIRECT_URI, testCallback))
                .thenReturn(new TokenPair("access", "refresh"));

        final TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals("access", token.AccessToken.Value);
        assertEquals("refresh", token.RefreshToken.Value);
    }

    @Test
    public void getTokenByRefreshToken_if_existingAccessTokenNotValid()
            throws URISyntaxException, InterruptedException, ExecutionException, IOException, AuthorizationException {
        when(mockOAuth2UseragentValidator.isOAuth2ProviderAvailable()).thenReturn(false);
        when(mockAzureAuthority.acquireToken(clientId.toString(), TEST_RESOURCE, TEST_REDIRECT_URI, testCallback))
                .thenReturn(new TokenPair("access", "refresh"));

        final TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals("access", token.AccessToken.Value);
        assertEquals("refresh", token.RefreshToken.Value);
    }

    @Test
    public void getTokenByAcquireAuthenticationResult_if_nothing_is_available()
            throws URISyntaxException, InterruptedException, ExecutionException, IOException, AuthorizationException {
        when(mockOAuth2UseragentValidator.isOAuth2ProviderAvailable()).thenReturn(false);
        final OAuth2Authenticator underTest = new OAuth2Authenticator(TEST_RESOURCE,
                clientId.toString(),
                TEST_REDIRECT_URI,
                mockStore,
                mockOAuth2UseragentValidator,
                null /* no callback specified */);

        final TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals(null, token);
    }

    @Test
    public void typeIsOAuth2() {
        assertEquals("OAuth2", underTest.getAuthType());
    }

    @Test
    public void oauth2IsSupported() {
        assertTrue(underTest.isOAuth2TokenSupported());

        assertFalse(underTest.isCredentialSupported());
        assertFalse(underTest.isPersonalAccessTokenSupported());
    }

}