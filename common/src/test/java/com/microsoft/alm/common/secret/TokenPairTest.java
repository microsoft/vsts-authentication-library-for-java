// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.secret;

import com.microsoft.alm.common.secret.TokenPair;
import com.microsoft.alm.common.helpers.StringHelperTest;
import com.microsoft.alm.common.helpers.XmlHelper;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

import static org.junit.Assert.assertEquals;

public class TokenPairTest {

    @Test
    public void xmlSerialization_roundTrip() throws Exception {
        final TokenPair tokenPair =
            new TokenPair("9297fb18-46d0-4846-97ca-ab8dd3b55729", "d15281b1-03f1-4581-90d3-4527d9cf4147");
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document serializationDoc = builder.newDocument();

        final Element element = tokenPair.toXml(serializationDoc);

        serializationDoc.appendChild(element);
        final String actualXmlString = XmlHelper.toString(serializationDoc);
        final String expectedXmlString =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
                        "<value>\n" +
                        "    <accessToken>9297fb18-46d0-4846-97ca-ab8dd3b55729</accessToken>\n" +
                        "    <refreshToken>d15281b1-03f1-4581-90d3-4527d9cf4147</refreshToken>\n" +
                        "</value>";
        StringHelperTest.assertLinesEqual(expectedXmlString, actualXmlString);

        final ByteArrayInputStream bais = new ByteArrayInputStream(actualXmlString.getBytes());
        final Document deserializationDoc = builder.parse(bais);
        final Element rootNode = deserializationDoc.getDocumentElement();

        final TokenPair actualTokenPair = TokenPair.fromXml(rootNode);

        assertEquals(tokenPair.AccessToken.Value, actualTokenPair.AccessToken.Value);
        assertEquals(tokenPair.RefreshToken.Value, actualTokenPair.RefreshToken.Value);
    }

    @Test
    public void accessTokenResponse_RFC6749() {
        final String input =
            "     {\n" +
            "       \"access_token\":\"2YotnFZFEjr1zCsicMWpAA\",\n" +
            "       \"token_type\":\"example\",\n" +
            "       \"expires_in\":3600,\n" +
            "       \"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\",\n" +
            "       \"example_parameter\":\"example_value\"\n" +
            "     }";

        final TokenPair actual = new TokenPair(input);

        Assert.assertEquals("2YotnFZFEjr1zCsicMWpAA", actual.AccessToken.Value);
        Assert.assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", actual.RefreshToken.Value);
        Assert.assertEquals("3600.0", actual.Parameters.get("expires_in"));
        Assert.assertEquals("example_value", actual.Parameters.get("example_parameter"));
        Assert.assertEquals("example", actual.Parameters.get("token_type"));
    }

}
