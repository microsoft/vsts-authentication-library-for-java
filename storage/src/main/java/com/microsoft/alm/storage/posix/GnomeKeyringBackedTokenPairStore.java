// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.common.helpers.Debug;
import com.microsoft.alm.common.secret.TokenPair;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.microsoft.alm.common.helpers.LoggingHelper.logError;

public class GnomeKeyringBackedTokenPairStore extends GnomeKeyringBackedSecureStore<TokenPair> {

    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedTokenPairStore.class);

    @Override
    protected String serialize(final TokenPair tokenPair) {
        Debug.Assert(tokenPair != null, "TokenPair cannot be null");

        return TokenPair.toXmlString(tokenPair);
    }

    @Override
    protected TokenPair deserialize(final String secret) {
        Debug.Assert(secret != null, "secret cannot be null");

        try {
            return TokenPair.fromXmlString(secret);
        } catch (final Exception e) {
            logError(logger, "Failed to deserialize the stored secret. Return null.", e);
            return null;
        }
    }

    @Override
    protected String getType() {
        return "OAuth2Token";
    }
}
