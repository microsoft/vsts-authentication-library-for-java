// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.secret;

import com.microsoft.alm.common.secret.Credential;
import com.microsoft.alm.common.helpers.StringHelperTest;
import com.microsoft.alm.common.helpers.XmlHelper;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.LinkedHashMap;
import java.util.Map;

public class CredentialTest {

    @Test
    public void xmlSerialization_roundTrip() throws Exception {
        final Credential credential = new Credential("douglas.adams", "42");
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document serializationDoc = builder.newDocument();

        final Element element = credential.toXml(serializationDoc);

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

        final Credential actualCredential = Credential.fromXml(rootNode);

        Assert.assertEquals(credential.Username, actualCredential.Username);
        Assert.assertEquals(credential.Password, actualCredential.Password);
    }

    @Test
    public void contributeHeader() throws Exception {
        final Credential credential = new Credential("douglas.adams", "42");
        final Map<String, String> headers = new LinkedHashMap<String, String>();

        credential.contributeHeader(headers);

        final String actual = headers.get("Authorization");
        Assert.assertEquals("Basic ZG91Z2xhcy5hZGFtczo0Mg==", actual);
    }
}
