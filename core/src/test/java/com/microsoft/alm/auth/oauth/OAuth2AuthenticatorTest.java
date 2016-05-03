// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.helpers.Action;
import com.microsoft.alm.oauth2.useragent.AuthorizationException;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.SecretStore;
import com.microsoftopentechnologies.auth.AuthenticationResult;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuth2AuthenticatorTest {

    private OAuth2Authenticator underTest;

    private SecretStore<TokenPair> mockStore;

    private AzureAuthority mockAzureAuthority;

    private OAuth2UseragentValidator mockOAuth2UseragentValidator;

    private Action<DeviceFlowResponse> testCallback;

    private UUID clientId = UUID.randomUUID();

    @Before
    public void setUp() throws Exception {
        mockStore = mock(SecretStore.class);
        mockAzureAuthority = mock(AzureAuthority.class);
        mockOAuth2UseragentValidator = mock(OAuth2UseragentValidator.class);
        testCallback = new Action<DeviceFlowResponse>() {
            @Override
            public void call(final DeviceFlowResponse deviceFlowResponse) {
                // do nothing on purpose
            }
        };

        underTest = new OAuth2Authenticator("test_resource",
                clientId.toString(),
                URI.create("https://testredirect.com"),
                mockStore,
                mockAzureAuthority,
                mockOAuth2UseragentValidator,
                testCallback);
    }

    @Test
    public void getTokenByAcquireToken_if_oauth2_useragent_available()
                throws URISyntaxException, AuthorizationException {
        when(mockOAuth2UseragentValidator.oauth2UserAgentAvailable()).thenReturn(true);
        when(mockAzureAuthority.acquireToken(clientId.toString(), "test_resource",
                new URI("https://testredirect.com"), underTest.POPUP_QUERY_PARAM))
                .thenReturn(new TokenPair("access", "refresh"));

        TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals("access", token.AccessToken.Value);
        assertEquals("refresh", token.RefreshToken.Value);

    }

    @Test
    public void getTokenByAcquireAuthenticationResult_if_oauth2_useragent_not_available()
            throws URISyntaxException, InterruptedException, ExecutionException, IOException, AuthorizationException {
        when(mockOAuth2UseragentValidator.oauth2UserAgentAvailable()).thenReturn(false);
        when(mockAzureAuthority.acquireAuthenticationResult(clientId.toString(), "test_resource",
                new URI("https://testredirect.com")))
                .thenReturn(new AuthenticationResult("AccessTokenType", "access", "refresh", 0, null, null));

        TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals("access", token.AccessToken.Value);
        assertEquals("refresh", token.RefreshToken.Value);
    }

    @Test
    public void getTokenByAcquireAuthenticationResult_if_neither_browser_is_available()
            throws URISyntaxException, InterruptedException, ExecutionException, IOException, AuthorizationException {
        when(mockOAuth2UseragentValidator.oauth2UserAgentAvailable()).thenReturn(false);
        when(mockAzureAuthority.acquireAuthenticationResult(clientId.toString(), "test_resource",
                new URI("https://testredirect.com")))
                .thenThrow(new IOException("Unable to launch local web server"));
        when(mockAzureAuthority.acquireToken(clientId.toString(), "test_resource", testCallback)).thenReturn(new TokenPair("access", "refresh"));

        final TokenPair token = underTest.getOAuth2TokenPair();

        assertEquals("access", token.AccessToken.Value);
        assertEquals("refresh", token.RefreshToken.Value);
    }

    @Test
    public void getTokenByAcquireAuthenticationResult_if_nothing_is_available()
            throws URISyntaxException, InterruptedException, ExecutionException, IOException, AuthorizationException {
        when(mockOAuth2UseragentValidator.oauth2UserAgentAvailable()).thenReturn(false);
        when(mockAzureAuthority.acquireAuthenticationResult(clientId.toString(), "test_resource",
                new URI("https://testredirect.com")))
                .thenThrow(new IOException("Unable to launch local web server"));
        final OAuth2Authenticator underTest = new OAuth2Authenticator("test_resource",
                clientId.toString(),
                URI.create("https://testredirect.com"),
                mockStore,
                mockAzureAuthority,
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