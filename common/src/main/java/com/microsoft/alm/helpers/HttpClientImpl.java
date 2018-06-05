// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

public class HttpClientImpl implements HttpClient {

    private static final Logger logger = LoggerFactory.getLogger(HttpClientImpl.class);

    public final Map<String, String> Headers = new LinkedHashMap<String, String>();

    public HttpClientImpl(final String userAgent) {
        Headers.put("User-Agent", userAgent);
    }

    private void ensureOK(final HttpURLConnection connection) throws IOException {
        final int statusCode = connection.getResponseCode();
        if (statusCode != HttpURLConnection.HTTP_OK) {
            InputStream errorStream = null;
            try {
                errorStream = connection.getErrorStream();
                String content = "";
                if (errorStream != null) {
                    content = IOHelper.readToString(errorStream);
                }
                final String template = "HTTP request failed with code %1$d: %2$s";
                final String message = String.format(template, statusCode, content);
                throw new IOException(message);
            } finally {
                IOHelper.closeQuietly(errorStream);
            }
        }
    }

    private static String readToString(final HttpURLConnection connection) throws IOException {
        return readToString(connection.getInputStream());
    }

    private static String readErrorToString(final HttpURLConnection connection) throws IOException {
        return readToString(connection.getErrorStream());
    }

    private static String readToString(final InputStream responseStream) throws IOException {
        final String responseContent;
        try {
            responseContent = IOHelper.readToString(responseStream);
        } finally {
            IOHelper.closeQuietly(responseStream);
        }
        return responseContent;
    }

    HttpURLConnection createConnection(final URI uri, final String method, final Action<HttpURLConnection> interceptor) {
        final URL url;
        try {
            url = uri.toURL();
        } catch (final MalformedURLException e) {
            throw new Error(e);
        }

        final HttpURLConnection connection;
        try {
            connection = (HttpURLConnection) url.openConnection();
        } catch (final IOException e) {
            throw new Error(e);
        }

        try {
            connection.setRequestMethod(method);
        } catch (final ProtocolException e) {
            throw new Error(e);
        }

        for (final Map.Entry<String, String> entry : Headers.entrySet()) {
            final String key = entry.getKey();
            final String value = entry.getValue();
            connection.setRequestProperty(key, value);
        }

        if (interceptor != null) {
            interceptor.call(connection);
        }

        return connection;
    }

    private HttpURLConnection head(final URI uri) throws IOException {
        return head(uri, null);
    }

    private HttpURLConnection head(final URI uri, final Action<HttpURLConnection> interceptor) throws IOException {
        final HttpURLConnection connection = createConnection(uri, "HEAD", interceptor);
        connection.connect();

        return connection;
    }

    @Override
    public Map<String, String> getHeaders() {
        return Headers;
    }

    @Override
    public String getHeaderField(final URI uri, final String header) throws IOException {
        return getHeaderField(uri, header, new Action<HttpURLConnection>() {
            @Override
            public void call(final HttpURLConnection conn) {
                conn.setInstanceFollowRedirects(false);
            }
        });
    }

    private String getHeaderField(URI uri, String header, Action<HttpURLConnection> interceptor) throws IOException {
        final HttpURLConnection connection = this.head(uri, interceptor);

        return connection.getHeaderField(header);
    }

    private HttpURLConnection get(final URI uri) throws IOException {
        return get(uri, null);
    }

    private HttpURLConnection get(final URI uri, final Action<HttpURLConnection> interceptor) throws IOException {
        final HttpURLConnection connection = createConnection(uri, "GET", interceptor);
        connection.setDoInput(true);

        return connection;
    }

    @Override
    public String getGetResponseText(URI uri) throws IOException {
        final HttpURLConnection response = this.get(uri);
        this.ensureOK(response);

        return readToString(response);
    }

    @Override
    public String getGetResponseText(URI uri, final int timeout) throws IOException {
        final HttpURLConnection response = this.get(uri, new Action<HttpURLConnection>() {
            @Override
            public void call(HttpURLConnection httpURLConnection) {
                httpURLConnection.setConnectTimeout(timeout);
            }
        });
        this.ensureOK(response);

        return readToString(response);
    }

    private HttpURLConnection post(final URI uri, final StringContent content) throws IOException {
        return post(uri, content, new Action<HttpURLConnection>() {
            @Override
            public void call(final HttpURLConnection conn) {
                conn.setUseCaches(false);
            }
        });
    }

    private HttpURLConnection post(final URI uri, final StringContent content, final Action<HttpURLConnection> interceptor) throws IOException {
        final HttpURLConnection connection = createConnection(uri, "POST", interceptor);
        connection.setDoInput(true);
        connection.setDoOutput(true);

        content.write(connection);

        return connection;
    }

    @Override
    public String getPostResponseText(URI uri, StringContent content) throws IOException {
        final HttpURLConnection response = this.post(uri, content);
        this.ensureOK(response);

        return readToString(response);
    }

    @Override
    public HttpResponse getPostResponse(URI uri, StringContent content) throws IOException {
        final HttpResponse response = new HttpResponse();
        final HttpURLConnection conn = this.post(uri, content);

        response.status = conn.getResponseCode();
        if (isSuccessful(response.status)) {
            response.responseText = readToString(conn);
        } else {
            response.errorText = readErrorToString(conn);
        }

        return response;
    }

    private boolean isSuccessful(final int statusCode) {
        // https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
        // 2xx successful
        return statusCode > 199 && statusCode < 300;
    }
}
