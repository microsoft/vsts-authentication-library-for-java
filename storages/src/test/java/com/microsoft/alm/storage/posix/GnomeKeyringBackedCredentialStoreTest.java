// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.secret.Credential;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.*;

public class GnomeKeyringBackedCredentialStoreTest {

    GnomeKeyringBackedCredentialStore underTest;

    @Before
    public void setUp() throws Exception {
        underTest = new GnomeKeyringBackedCredentialStore();
    }

    @Test
    public void serializeDeserialize_specialChars() {
        final String username = "!@#$%^&*~";
        final String password = ":'\"/";
        final Credential cred = new Credential(username, password);
        final Credential processedCred = underTest.deserialize(underTest.serialize(cred));
        assertEquals(username, processedCred.Username);
        assertEquals(password, processedCred.Password);
    }


    @Test
    @Ignore("Only work on Linux platform with gnome-keyring support, needs to be run manually, in interactive mode")
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