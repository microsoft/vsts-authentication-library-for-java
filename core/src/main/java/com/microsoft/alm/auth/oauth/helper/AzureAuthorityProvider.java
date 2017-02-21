// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth.helper;

import com.microsoft.alm.auth.oauth.AzureAuthority;
import com.microsoft.alm.auth.oauth.OAuth2Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.UUID;

/**
 * Provide tenant appropriate AzureAuthority
 */
public class AzureAuthorityProvider {
    private static final Logger logger = LoggerFactory.getLogger(AzureAuthorityProvider.class);

    public AzureAuthority getAzureAuthority(final URI uri) throws IOException {
        if (uri == OAuth2Authenticator.APP_VSSPS_VISUALSTUDIO) {
            return AzureAuthority.DefaultAzureAuthority;
        }

        logger.debug("Lookup tenant id for {}", uri);
        final UUID tenantId = AzureAuthority.detectTenantId(uri);
        logger.debug("tenant id for {} is {}", uri, tenantId);
        if (tenantId == null) {
            // backed by MSA account
            return AzureAuthority.DefaultAzureAuthority;
        }

        return new AzureAuthority(AzureAuthority.AuthorityHostUrlBase + "/" + tenantId);
    }

}
