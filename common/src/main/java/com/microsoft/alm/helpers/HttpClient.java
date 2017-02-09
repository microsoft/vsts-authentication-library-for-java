// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.helpers;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;

public interface HttpClient {

    /**
     * Return a reference to the headers this request will use
     *
     * Must return a reference, not a clone or a copy
     *
     * @return the reference of headers will be used for this request
     */
    Map<String, String> getHeaders();

    /**
     * Make a HEAD call and get the header value returned
     *
     * @param uri target uri
     * @param header the header to retrieve
     * @return value of the header, null if this header doesn't exist
     * @throws IOException
     */
    String getHeaderField(URI uri, String header) throws IOException;

    /**
     * Read response from a GET HTTP call to the targetUri
     *
     * @param uri
     * @return response
     * @throws IOException if response status code is not 2xx, the error message is the error from server.
     * stream from the connection
     */
    String getGetResponseText(URI uri) throws IOException;
    String getGetResponseText(URI uri, int Timeout) throws IOException;

    /**
     * Read the response from a POST HTTP call to the target uri
     * @param uri
     * @param content
     * @return response
     * @throws IOException if response status code is not 2xx, the error message is the error from server.
     */
    String getPostResponseText(URI uri, StringContent content) throws IOException;

    /**
     * Read the response from a POST HTTP call, but don't throw any exception even if the call is not successful
     * @param uri
     * @param content
     * @return
     * @throws IOException
     */
    HttpResponse getPostResponse(URI uri, StringContent content) throws IOException;
}
