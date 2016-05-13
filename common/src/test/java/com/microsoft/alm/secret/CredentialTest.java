// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.secret;

import org.junit.Assert;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;

public class CredentialTest {

    @Test
    public void contributeHeader() throws Exception {
        final Credential credential = new Credential("douglas.adams", "42");
        final Map<String, String> headers = new LinkedHashMap<String, String>();

        credential.contributeHeader(headers);

        final String actual = headers.get("Authorization");
        Assert.assertEquals("Basic ZG91Z2xhcy5hZGFtczo0Mg==", actual);
    }
}
