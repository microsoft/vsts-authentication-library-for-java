// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.windows;

import com.microsoft.alm.auth.secret.Token;
import com.microsoft.alm.auth.secret.TokenType;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CredManagerBackedTokenStoreTest {

    private CredManagerBackedTokenStore underTest;

    @Before
    public void setup() {
        underTest = new CredManagerBackedTokenStore();
    }

    //low value basic tests that should auto run
    @Test
    public void testCreate() throws Exception {
        final String secretValue = "my secret";
        Token token = underTest.create("do not care", secretValue);

        assertEquals("Secret not correct", secretValue, token.Value);
    }

    @Test
    public void testGetUsername() throws Exception {
        final Token token = new Token("do not care", TokenType.Personal);
        assertEquals("Username is not correct", CredManagerBackedTokenStore.TOKEN_USERNAME,
                underTest.getUsername(token));
    }

    @Test
    public void testGetCredentialBlob() throws Exception {
        final Token token = new Token("do not care", TokenType.Personal);
        assertEquals("CredentialBlob is not correct", "do not care",
                underTest.getCredentialBlob(token));
    }

    @Ignore("Only works on Windows platform, must run manually")
    @Test
    public void e2eTestStoreReadDelete() {
        final Token token = new Token("do not care", TokenType.Personal);
        final String key = "CredManagerTest:http://test.com:Token";

        // this should have been saved to cred manager, it would be good if you can set a breakpoint
        // and manaully verify this now
        underTest.add(key, token);

        Token readToken = underTest.get(key);

        assertEquals("Retrieved token is different", token.Value, readToken.Value);

        // The token under the specified key should be deleted now, it's a good idea to manually verify this now
        boolean deleted = underTest.delete(key);
        assertTrue("Test token should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Test token deleted twice, did first delete fail?", deleted);

        readToken = underTest.get(key);
        assertNull("Token can still be read from store?  Did delete fail?", readToken);
    }

}