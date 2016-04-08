// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage;

import com.microsoft.alm.secret.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.microsoft.alm.helpers.LoggingHelper.logError;

public class InsecureFileBackedCredentialStore implements SecretStore<Credential> {

    private static Logger logger = LoggerFactory.getLogger(InsecureFileBackedCredentialStore.class);

    private static InsecureFileBackend fileBackend = InsecureFileBackend.getInstance();

    @Override
    public Credential get(String key) {
        return fileBackend.readCredentials(key);
    }

    @Override
    public boolean delete(String key) {
        return fileBackend.delete(key);
    }

    @Override
    public boolean add(String key, Credential secret) {
        try {
            fileBackend.writeCredential(key, secret);

            return true;
        } catch (final Throwable t) {
            logError(logger, "Failed to add secret to file backed credential store.", t);

            return false;
        }
    }

    @Override
    public boolean isSecure() {
        return false;
    }
}
