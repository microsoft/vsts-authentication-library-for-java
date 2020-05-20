// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage;

import com.microsoft.alm.common.secret.Token;
import com.microsoft.alm.common.storage.SecretStore;
import com.microsoft.alm.storage.StorageProvider.NonPersistentStoreGenerator;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static com.microsoft.alm.storage.StorageProvider.SecureOption;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class StorageProviderTest {

    private NonPersistentStoreGenerator<Token> generator = new NonPersistentStoreGenerator<Token>() {
        @Override
        public SecretStore<Token> getInsecureNonPersistentStore() {
            return getStore(false);
        }

        @Override
        public SecretStore<Token> getSecureNonPersistentStore() {
            return null;
        }
    };

    @Test
    public void withAvailableSecureStore_shouldReturnSecureStore() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<Token> actual = StorageProvider.getStore(true, SecureOption.MUST, candidates, generator);
        assertTrue(actual.isSecure());
    }

    @Test
    public void noAvailableSecureStore_shouldReturnNull() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();

        final SecretStore<Token> actual = StorageProvider.getStore(true, SecureOption.MUST, candidates, generator);
        assertNull(actual);
    }

    @Test
    public void nonPersisted_MustBeSecure_shouldUseGenerator() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<Token> actual = StorageProvider.getStore(false, SecureOption.MUST, candidates, generator);
        assertNull(actual);
    }

    @Test
    public void nonPersisted_doNotCareSecurity_shouldUseGenerator() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<Token> actual = StorageProvider.getStore(false, SecureOption.PREFER, candidates, generator);
        assertFalse(actual.isSecure());
    }

    private SecretStore<Token> getStore(final boolean secure) {
        return new SecretStore<Token>() {
            @Override
            public Token get(String key) { return null; }

            @Override
            public boolean delete(String key) { return false; }

            @Override
            public boolean add(String key, Token secret) { return false; }

            @Override
            public boolean isSecure() {
                return secure;
            }
        };
    }

}