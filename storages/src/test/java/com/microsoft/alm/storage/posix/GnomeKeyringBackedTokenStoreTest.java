// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenType;
import org.junit.Before;
import org.junit.Test;

import java.util.UUID;

import static org.junit.Assert.assertEquals;

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

}