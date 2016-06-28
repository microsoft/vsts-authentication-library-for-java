// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.oauth2.useragent.Provider;
import com.microsoft.alm.oauth2.useragent.ProviderScanner;
import com.microsoft.alm.oauth2.useragent.StandardWidgetToolkitProvider;
import com.microsoft.alm.oauth2.useragent.UserAgentImpl;

import java.util.List;
import java.util.Map;

/**
 * This class verifies the availability of OAuth2-useragent on the current platform
 */
public class OAuth2UseragentValidator {

    private final ProviderScanner scanner = new UserAgentImpl();

    /**
     * Determines if oauth2 useragent can be used on the current running system.
     *
     * @return {@code true} if oauth2-useragent can be used 100% positively
     *         {@code false} with any doubts
     */
    public boolean isOAuth2ProviderAvailable() {
        // not tests are worthy adding since I don't control this implementation
        final Provider provider = scanner.findCompatibleProvider();

        return provider != null;
    }

    public boolean isOnlyMissingRuntimeFromSwtProvider() {
        final Map<Provider, List<String>> unmetProviderRequirements = scanner.getUnmetProviderRequirements();
        final List<String> unmetSwtProviderRequirement = unmetProviderRequirements.get(Provider.STANDARD_WIDGET_TOOLKIT);

        if (unmetSwtProviderRequirement != null && unmetSwtProviderRequirement.size() == 1) {
            return unmetSwtProviderRequirement.get(0).contains(StandardWidgetToolkitProvider.getDefaultSwtJarPath());
        }

        return false;
    }
}
