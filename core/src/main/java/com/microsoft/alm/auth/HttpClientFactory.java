// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth;

import com.microsoft.alm.auth.oauth.Global;
import com.microsoft.alm.helpers.HttpClient;
import com.microsoft.alm.helpers.HttpClientImpl;

public class HttpClientFactory {

    public HttpClient createHttpClient() {
        return new HttpClientImpl(Global.getUserAgent());
    }
}
