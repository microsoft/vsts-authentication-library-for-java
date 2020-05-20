// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.helpers;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

public class UriHelper {
    public static final String HOST_AZURE = "azure.com";
    public static final String HOST_AZURE_ORG = ".azure.com";

    private static final Pattern PAIR_SEPARATOR = Pattern.compile("&");
    private static final Pattern NAME_VALUE_SEPARATOR = Pattern.compile("=");

    public static final String UTF_8 = "UTF-8";

    public static boolean isWellFormedUriString(final String uriString) {
        try {
            new URI(uriString);
            return true;
        } catch (final URISyntaxException ignored) {
            return false;
        }
    }

    public static QueryString deserializeParameters(final String s) {
        final QueryString result = new QueryString();

        if (StringHelper.isNullOrWhiteSpace(s)) {
            return result;
        }

        final String trimmed = s.trim();
        final String[] pairs = PAIR_SEPARATOR.split(trimmed);

        for (final String pair : pairs) {
            final String trimmedPair = pair.trim();
            if (trimmedPair.length() == 0) {
                continue;
            }
            final String[] nameAndValue = NAME_VALUE_SEPARATOR.split(pair, 2);
            try {
                final String name = URLDecoder.decode(nameAndValue[0], UTF_8);
                final String value;
                value = nameAndValue.length == 2 ? URLDecoder.decode(nameAndValue[1], UTF_8) : null;
                result.put(name, value);
            } catch (final UnsupportedEncodingException e) {
                throw new Error(e);
            }

        }
        return result;
    }

    public static String serializeParameters(final Map<String, String> parameters) {
        try {
            final StringBuilder sb = new StringBuilder();
            final Iterator<Map.Entry<String, String>> iterator = parameters.entrySet().iterator();
            if (iterator.hasNext()) {
                Map.Entry<String, String> entry;
                String key;
                String encodedKey;
                String value;
                String encodedValue;

                entry = iterator.next();
                key = entry.getKey();
                encodedKey = URLEncoder.encode(key, UTF_8);
                sb.append(encodedKey);
                value = entry.getValue();
                if (value != null) {
                    encodedValue = URLEncoder.encode(value, UTF_8);
                    sb.append('=').append(encodedValue);
                }
                while (iterator.hasNext()) {
                    sb.append('&');
                    entry = iterator.next();
                    key = entry.getKey();
                    encodedKey = URLEncoder.encode(key, UTF_8);
                    sb.append(encodedKey);
                    value = entry.getValue();
                    if (value != null) {
                        encodedValue = URLEncoder.encode(value, UTF_8);
                        sb.append('=').append(encodedValue);
                    }
                }
            }
            return sb.toString();
        } catch (final UnsupportedEncodingException e) {
            throw new Error(e);
        }

    }

    public static boolean isAzureHost(final URI uri) {
        if ((uri != null && uri.getHost() != null)
                && (uri.getHost().equalsIgnoreCase(HOST_AZURE) || StringHelper.endsWithIgnoreCase(uri.getHost(), HOST_AZURE_ORG))) {
            return true;
        }
        return false;
    }

    public static String getFullAccount(final URI uri) {
        if (isAzureHost(uri)) {
            // Get the account which will be in the form azure.com/account
            // If we don't have a path with length > 0 check for the mseng@azure.com case
            // If we don't match the if or else if, we likely have an issue
            String[] paths = uri.getPath().split("/");
            if (paths.length > 1) {
                return uri.getHost() + "/" + paths[1];
            }
            else if (!StringHelper.isNullOrWhiteSpace(uri.getUserInfo())) {
                return uri.getHost() + "/" + uri.getUserInfo();
            }
        }
        return uri.getHost();
    }
}
