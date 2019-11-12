// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.common.secret.Credential;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class GnomeKeyringBackedCredentialStoreIT {

    GnomeKeyringBackedCredentialStore underTest;

    @Before
    public void setUp() throws Exception {
        //Only test on platform that has gnome-keyring support
        assumeTrue(GnomeKeyringBackedSecureStore.isGnomeKeyringSupported());

        underTest = new GnomeKeyringBackedCredentialStore();
    }

    @Test
    public void saveCredential() {
        final String testKey = "http://thisisatestkey";

        final Credential credential = new Credential("username", "pass:\"word");
        boolean added = underTest.add(testKey, credential);

        assertTrue(added);

        final Credential readValue = underTest.get(testKey);

        assertEquals(credential.Username, readValue.Username);
        assertEquals(credential.Password, readValue.Password);

        boolean deleted = underTest.delete(testKey);
        assertTrue(deleted);

        final Credential nonExistent = underTest.get(testKey);
        assertNull(nonExistent);
    }
}