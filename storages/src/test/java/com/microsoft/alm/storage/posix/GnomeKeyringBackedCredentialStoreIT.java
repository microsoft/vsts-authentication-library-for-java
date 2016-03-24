// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.*;

public class GnomeKeyringBackedCredentialStoreIT {

    GnomeKeyringBackedCredentialStore underTest;

    @Test
    public void saveCredential() {
        if (GnomeKeyringBackedSecureStore.isGnomeKeyringSupported()) {
            underTest = new GnomeKeyringBackedCredentialStore();
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
}