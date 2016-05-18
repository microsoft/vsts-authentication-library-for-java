// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.secret;

import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.StringHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

public abstract class Secret {

    private static final Logger logger = LoggerFactory.getLogger(Secret.class);

    public static String uriToName(final URI targetUri, final String namespace) {
        final String TokenNameBaseFormat = "%1$s:%2$s://%3$s";
        final String TokenNamePortFormat = TokenNameBaseFormat + ":%4$s";

        Debug.Assert(targetUri != null, "The targetUri parameter is null");

        logger.debug("Secret::uriToName");

        String targetName = null;
        // trim any trailing slashes and/or whitespace for compat with git-credential-winstore
        final String trimmedHostUrl = StringHelper.trimEnd(StringHelper.trimEnd(targetUri.getHost(), '/', '\\'));


        if (targetUri.getPort() == -1 /* isDefaultPort */) {
            targetName = String.format(TokenNameBaseFormat, namespace, targetUri.getScheme(), trimmedHostUrl);
        } else {
            targetName = String.format(TokenNamePortFormat, namespace, targetUri.getScheme(), trimmedHostUrl, targetUri.getPort());
        }

        logger.debug("   target name = {}", targetName);

        return targetName;
    }

    public interface IUriNameConversion {
        String DEFAULT_NAMESPACE = "java-auth";

        String convert(final URI targetUri, final String namespace);
    }

    public static IUriNameConversion DefaultUriNameConversion = new IUriNameConversion() {

        @Override
        public String convert(final URI targetUri, final String namespace) {
            return Secret.uriToName(targetUri, namespace);
        }
    };
}
