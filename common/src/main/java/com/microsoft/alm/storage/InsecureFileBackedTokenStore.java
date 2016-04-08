// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage;

import com.microsoft.alm.secret.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.microsoft.alm.helpers.LoggingHelper.logError;

public class InsecureFileBackedTokenStore implements SecretStore<Token> {

    private static Logger logger = LoggerFactory.getLogger(InsecureFileBackedTokenStore.class);

    private static InsecureFileBackend fileBackend = InsecureFileBackend.getInstance();

    @Override
    public Token get(String key) {
        return fileBackend.readToken(key);
    }

    @Override
    public boolean delete(String key) {
        return fileBackend.delete(key);
    }

    @Override
    public boolean add(String key, Token secret) {
        try {
            fileBackend.writeToken(key, secret);

            return true;
        } catch (final Throwable t) {
            logError(logger, "Failed to add secret to file backed token store.", t);
            return false;
        }
    }

    @Override
    public boolean isSecure() {
        return false;
    }
}
