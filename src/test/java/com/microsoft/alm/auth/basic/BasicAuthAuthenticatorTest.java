// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.basic;

import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.secret.Credential;
import com.microsoft.alm.storage.SecretStore;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class BasicAuthAuthenticatorTest {

    private BasicAuthAuthenticator underTest;

    private SecretStore<Credential> mockStore;
    @Before
    public void setUp() throws Exception {
        mockStore = Mockito.mock(SecretStore.class);

        underTest = new BasicAuthAuthenticator(mockStore, new CredentialPrompt(){
            @Override
            public Credential prompt(URI target) {
                return new Credential("user", "pass");
            }
        });
    }

    @Test
    public void noCredentialStoredShouldPrompt() {
        URI uri = URI.create("http://test.com");
        String key = underTest.getKey(uri);
        Credential credential = underTest.getCredential(uri);

        // should call get once and don't get anything
        verify(mockStore).get(key);

        // and invoke the credential prompt which returns back users:pass
        assertEquals("user", credential.Username);
        assertEquals("pass", credential.Password);

        // and then store this value
        verify(mockStore).add(key, credential);
    }

    @Test
    public void withCredentialStoredRetrieveStoredValue() {
        URI uri = URI.create("http://test.com");
        String key = underTest.getKey(uri);

        when(mockStore.get(key)).thenReturn(new Credential("storedUser", "storedPass"));

        Credential credential = underTest.getCredential(uri);

        // should return stored value instead of default prompted value
        assertEquals("storedUser", credential.Username);
        assertEquals("storedPass", credential.Password);

        verify(mockStore, never()).add(anyString(), any(Credential.class));
    }

    @Test
    public void promptBehaviorNeverShouldNotPrompt() {
        URI uri = URI.create("http://test.com");
        String key = underTest.getKey(uri);

        Credential credential = underTest.getCredential(uri, PromptBehavior.NEVER);
        // Store miss, and never prompt should return null
        assertNull(credential);
    }

    @Test
    public void typeIsBasic() {
        assertEquals("BasicAuth", underTest.getAuthType());
    }

    @Test
    public void credentialIsSupported() {
        assertTrue(underTest.isCredentialSupported());

        assertFalse(underTest.isOAuth2TokenSupported());
        assertFalse(underTest.isPersonalAccessTokenSupported());
    }
}