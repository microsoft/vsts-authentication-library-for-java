// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.secret.TokenType;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class GnomeKeyringBackedTokenStoreTest {

    GnomeKeyringBackedTokenStore underTest;

    @Before
    public void setUp() throws Exception {
        underTest = new GnomeKeyringBackedTokenStore();
    }

    @Test
    public void serializeDeserialize() {
        final Token token = new Token(UUID.randomUUID().toString(), TokenType.Personal);
        final Token processed = underTest.deserialize(underTest.serialize(token)) ;

        assertEquals(token.Value, processed.Value);
    }
    @Test
    @Ignore("Only work on Linux platform with gnome-keyring support")
    public void saveToken() {
        final String testKey = "http://thisisatestkey";

        final Token token = new Token("bi4295xkwev6djxej7hpffuoo4rzcqcogakubpu2sd7kopuoquaq", TokenType.Personal);
        boolean added = underTest.add(testKey, token);

        assertTrue(added);

        final Token readValue = underTest.get(testKey);

        assertEquals(token.Value, readValue.Value);

        boolean deleted = underTest.delete(testKey);
        assertTrue(deleted);

        final Token nonExistent = underTest.get(testKey);
        assertNull(nonExistent);
    }

}