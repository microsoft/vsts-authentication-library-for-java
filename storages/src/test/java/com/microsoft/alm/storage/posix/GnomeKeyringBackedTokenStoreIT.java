// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenType;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;
import org.junit.Test;

import static org.junit.Assert.*;

public class GnomeKeyringBackedTokenStoreIT {


    GnomeKeyringBackedTokenStore underTest;

    @Test
    public void saveToken() {
        if (GnomeKeyringBackedSecureStore.isGnomeKeyringSupported()) {
            underTest = new GnomeKeyringBackedTokenStore();
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
}