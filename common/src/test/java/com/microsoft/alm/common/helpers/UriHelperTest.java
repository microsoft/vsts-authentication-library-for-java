// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.helpers;

import com.microsoft.alm.common.helpers.UriHelper;
import com.microsoft.alm.common.helpers.QueryString;
import org.junit.Assert;
import org.junit.Test;

import java.net.URI;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class UriHelperTest {

    @Test
    public void deserializeParameters_null() throws Exception {
        final String input = null;

        final QueryString actual = UriHelper.deserializeParameters(input);

        assertMapEntries(actual);
    }

    @Test
    public void deserializeParameters_empty() throws Exception {
        final String input = "";

        final QueryString actual = UriHelper.deserializeParameters(input);

        assertMapEntries(actual);
    }

    @Test
    public void deserializeParameters_firstHasNameOnly() throws Exception {
        final String input = "nameOnly";

        final QueryString actual = UriHelper.deserializeParameters(input);

        assertMapEntries(actual,
                "nameOnly", null
        );
    }

    @Test
    public void deserializeParameters_firstHasNameValue() throws Exception {
        final String input = "name=value";

        final QueryString actual = UriHelper.deserializeParameters(input);

        assertMapEntries(actual,
                "name", "value"
        );
    }

    @Test
    public void deserializeParameters_secondHasNameOnly() throws Exception {
        final String input = "name=value&nameOnly";

        final QueryString actual = UriHelper.deserializeParameters(input);

        assertMapEntries(actual,
                "name", "value",
                "nameOnly", null
        );
    }

    @Test
    public void deserializeParameters_typical() throws Exception {
        final String input = "resource=a8860e8f-ca7d-4efe-b80d-4affab13d4ba&client_id=f7e11bcd-b50b-4869-ad88-8bdd6cbc8473&response_type=code&redirect_uri=https%3A%2F%2Fexample.com&client-request-id=06ac412b-8cc0-4ca5-b943-d9dc218abee6&prompt=login";

        final QueryString actual = UriHelper.deserializeParameters(input);

        assertMapEntries(actual,
                "resource", "a8860e8f-ca7d-4efe-b80d-4affab13d4ba",
                "client_id", "f7e11bcd-b50b-4869-ad88-8bdd6cbc8473",
                "response_type", "code",
                "redirect_uri", "https://example.com",
                "client-request-id", "06ac412b-8cc0-4ca5-b943-d9dc218abee6",
                "prompt", "login"
        );
    }

    private static void assertMapEntries(final Map<String, String> actualMap, final String... namesAndValues) {
        Assert.assertEquals("I need an even number of names and values", 0, namesAndValues.length % 2);

        final Set<Map.Entry<String, String>> actualEntries = actualMap.entrySet();
        final Iterator<Map.Entry<String, String>> aIt = actualEntries.iterator();
        for (int e = 0; e < namesAndValues.length; e += 2) {
            Assert.assertTrue(aIt.hasNext());
            final Map.Entry<String, String> actualPair = aIt.next();

            final String index = "At index " + (e / 2);
            Assert.assertEquals(index, namesAndValues[e], actualPair.getKey());
            Assert.assertEquals(index, namesAndValues[e + 1], actualPair.getValue());
        }
        Assert.assertFalse(aIt.hasNext());
    }

    @Test
    public void serializeParameters_firstHasNameOnly() throws Exception {
        final Map<String, String> input = new LinkedHashMap<String, String>();
        input.put("nameOnly", null);

        final String actual = UriHelper.serializeParameters(input);

        Assert.assertEquals("nameOnly", actual);
    }

    @Test
    public void serializeParameters_secondHasNameOnly() throws Exception {
        final Map<String, String> input = new LinkedHashMap<String, String>();
        input.put("name", "value");
        input.put("nameOnly", null);

        final String actual = UriHelper.serializeParameters(input);

        Assert.assertEquals("name=value&nameOnly", actual);
    }

    @Test
    public void serializeParameters_typical() throws Exception {
        final Map<String, String> input = new LinkedHashMap<String, String>();
        input.put("resource", "a8860e8f-ca7d-4efe-b80d-4affab13d4ba");
        input.put("client_id", "f7e11bcd-b50b-4869-ad88-8bdd6cbc8473");
        input.put("response_type", "code");
        input.put("redirect_uri", "https://example.com");
        input.put("client-request-id", "06ac412b-8cc0-4ca5-b943-d9dc218abee6");
        input.put("prompt", "login");

        final String actual = UriHelper.serializeParameters(input);

        Assert.assertEquals("resource=a8860e8f-ca7d-4efe-b80d-4affab13d4ba&client_id=f7e11bcd-b50b-4869-ad88-8bdd6cbc8473&response_type=code&redirect_uri=https%3A%2F%2Fexample.com&client-request-id=06ac412b-8cc0-4ca5-b943-d9dc218abee6&prompt=login", actual);
    }

    @Test
    public void getFullAccount_tests() throws Exception {
        Assert.assertEquals("msft.azure.com/account1", UriHelper.getFullAccount(URI.create("https://msft.azure.com/account1/blah")));
        Assert.assertEquals("azure.com/account1", UriHelper.getFullAccount(URI.create("https://azure.com/account1/blah")));
        Assert.assertEquals("azure.com/account1", UriHelper.getFullAccount(URI.create("https://azure.com/account1/blah/")));
        Assert.assertEquals("AZURE.COM/account1", UriHelper.getFullAccount(URI.create("https://AZURE.COM/account1/blah/")));
        Assert.assertEquals("msft.azure.com", UriHelper.getFullAccount(URI.create("https://msft.azure.com/")));
        Assert.assertEquals("visualstudio.com", UriHelper.getFullAccount(URI.create("https://visualstudio.com/defaultcollection/blah/")));
        Assert.assertEquals("VISUALSTUDIO.COM", UriHelper.getFullAccount(URI.create("https://VISUALSTUDIO.COM/defaultcollection/blah/")));
        Assert.assertEquals("azure.com/mseng", UriHelper.getFullAccount( URI.create("https://mseng@azure.com/mseng/VSOnline/_git/VSO")));
        Assert.assertEquals("AZURE.COM/mseng", UriHelper.getFullAccount( URI.create("https://mseng@AZURE.COM/mseng/")));
        Assert.assertEquals("azure.com/mseng", UriHelper.getFullAccount( URI.create("https://mseng@azure.com")));
        Assert.assertEquals("google.com", UriHelper.getFullAccount( URI.create("https://mseng@google.com")));
    }

    @Test
    public void IsOrganization_tests() {
        Assert.assertEquals(true, UriHelper.isAzureHost( URI.create("https://msft.azure.com/account1/blah")));
        Assert.assertEquals(true, UriHelper.isAzureHost( URI.create("https://azure.com/account1/blah/")));
        Assert.assertEquals(true, UriHelper.isAzureHost( URI.create("https://azure.com/account1/blah")));
        Assert.assertEquals(true, UriHelper.isAzureHost( URI.create("https://AZURE.COM/account1/blah/")));
        Assert.assertEquals(true, UriHelper.isAzureHost( URI.create("https://msft.azure.com/")));
        Assert.assertEquals(false, UriHelper.isAzureHost( URI.create("https://visualstudio.com/defaultcollection/blah/")));
        Assert.assertEquals(false, UriHelper.isAzureHost( URI.create("https://VISUALSTUDIO.COM/defaultcollection/blah/")));
        Assert.assertEquals(false, UriHelper.isAzureHost( URI.create("https://www.google.com")));
        Assert.assertEquals(true, UriHelper.isAzureHost( URI.create("https://mseng@azure.com/mseng/VSOnline/_git/VSO")));
        Assert.assertEquals(true, UriHelper.isAzureHost( URI.create("https://mseng@AZURE.COM/mseng/VSOnline/_git/VSO")));
        Assert.assertEquals(false, UriHelper.isAzureHost( URI.create("https://mseng@google.com/mseng/VSOnline/_git/VSO")));
    }
}
