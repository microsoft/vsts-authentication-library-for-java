// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static com.microsoft.alm.helpers.LoggingHelper.logError;

public class GnomeKeyringBackedCredentialStore extends GnomeKeyringBackedSecureStore<Credential> {

    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedCredentialStore.class);

    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    }

    @Override
    protected Credential deserialize(String secret) {
        Debug.Assert(secret != null, "secret cannot be null");

        try {
            final CredentialWrapper credentialWrapper = mapper.readValue(secret, CredentialWrapper.class);

            return new Credential(credentialWrapper.username, credentialWrapper.password);
        } catch (IOException e) {
            logError(logger, "Failed to deserialize credential.", e);
            return null;
        }
    }

    @Override
    protected String serialize(final Credential credential) {
        Debug.Assert(credential != null, "Credential cannot be null");

        final CredentialWrapper wrapper = new CredentialWrapper();
        wrapper.setUsername(credential.Username);
        wrapper.setPassword(credential.Password);

        try {
            return mapper.writeValueAsString(wrapper);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected String getType() {
        return "Credential";
    }

    public static class CredentialWrapper {
        private String username;
        private String password;

        public void setUsername(String username) {
            this.username = username;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}
