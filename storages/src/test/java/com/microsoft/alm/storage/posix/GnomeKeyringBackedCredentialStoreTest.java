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

}