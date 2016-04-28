// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.helpers;

import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.secret.TokenType;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class XmlHelperTest {

    XmlHelper underTest;

    @Before
    public void setUp() {
        underTest = new XmlHelper();
    }

    @Test
    public void xmlSerialization_roundTrip() throws Exception {
        final Credential credential = new Credential("douglas.adams", "42");
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document serializationDoc = builder.newDocument();

        final Element element = underTest.toXml(serializationDoc, credential);

        serializationDoc.appendChild(element);
        final String actualXmlString = XmlHelper.toString(serializationDoc);
        final String expectedXmlString =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
                        "<value>\n" +
                        "    <Password>42</Password>\n" +
                        "    <Username>douglas.adams</Username>\n" +
                        "</value>";
        StringHelperTest.assertLinesEqual(expectedXmlString, actualXmlString);

        final ByteArrayInputStream bais = new ByteArrayInputStream(actualXmlString.getBytes());
        final Document deserializationDoc = builder.parse(bais);
        final Element rootNode = deserializationDoc.getDocumentElement();

        final Credential actualCredential = underTest.fromXmlToCredential(rootNode);

        assertEquals(credential.Username, actualCredential.Username);
        assertEquals(credential.Password, actualCredential.Password);
    }

    @Test
    public void xmlTokenSerialization_roundTrip() throws Exception {
        final Token token = new Token("1", TokenType.Access);
        token.setTargetIdentity(UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document serializationDoc = builder.newDocument();

        final Element element = underTest.toXml(serializationDoc, token);

        serializationDoc.appendChild(element);
        final String actualXmlString = XmlHelper.toString(serializationDoc);
        final String expectedXmlString =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
                        "<value>\n" +
                        "    <Type>Access</Type>\n" +
                        "    <Value>1</Value>\n" +
                        "    <targetIdentity>ffffffff-ffff-ffff-ffff-ffffffffffff</targetIdentity>\n" +
                        "</value>";
        StringHelperTest.assertLinesEqual(expectedXmlString, actualXmlString);

        final ByteArrayInputStream bais = new ByteArrayInputStream(actualXmlString.getBytes());
        final Document deserializationDoc = builder.parse(bais);
        final Element rootNode = deserializationDoc.getDocumentElement();

        final Token actualToken = underTest.fromXmlToToken(rootNode);

        assertEquals(token.Value, actualToken.Value);
        assertEquals(token.Type, actualToken.Type);
        assertEquals(token.getTargetIdentity(), actualToken.getTargetIdentity());
    }

    @Test
    public void xmlTokenPairSerialization_roundTrip() throws Exception {
        final TokenPair tokenPair =
            new TokenPair("9297fb18-46d0-4846-97ca-ab8dd3b55729", "d15281b1-03f1-4581-90d3-4527d9cf4147");
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document serializationDoc = builder.newDocument();

        final Element element = underTest.toXml(serializationDoc, tokenPair);

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

        final TokenPair actualTokenPair = underTest.fromXmlToTokenPair(rootNode);

        assertEquals(tokenPair.AccessToken.Value, actualTokenPair.AccessToken.Value);
        assertEquals(tokenPair.RefreshToken.Value, actualTokenPair.RefreshToken.Value);
    }

}