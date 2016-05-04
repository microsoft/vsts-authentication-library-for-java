// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.helpers.QueryString;

public class AzureDeviceFlow extends DeviceFlowImpl {
    private String resource;

    private String redirectUri;

    public String getResource() {
        return resource;
    }

    public void setResource(final String resource) {
        this.resource = resource;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(final String redirectUri) {
        this.redirectUri = redirectUri;
    }

    @Override
    protected void contributeAuthorizationRequestParameters(final QueryString bodyParameters) {
        if (resource != null) {
            bodyParameters.put(OAuthParameter.RESOURCE, resource);
        }

        if (redirectUri != null) {
            bodyParameters.put(OAuthParameter.REDIRECT_URI, redirectUri);
        }
    }

    @Override
    protected DeviceFlowResponse buildDeviceFlowResponse(final String responseText) {
        return AzureDeviceFlowResponse.fromJson(responseText);
    }
}
