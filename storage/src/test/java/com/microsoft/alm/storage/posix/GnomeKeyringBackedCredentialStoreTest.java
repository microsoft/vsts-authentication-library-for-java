// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.common.secret.Credential;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

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
        final String serialized = underTest.serialize(cred);
        final Credential processedCred = underTest.deserialize(serialized);
        assertEquals(username, processedCred.Username);
        assertEquals(password, processedCred.Password);
    }

}