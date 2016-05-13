// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.StringHelper;
import com.microsoft.alm.helpers.XmlHelper;
import com.microsoft.alm.secret.TokenPair;
import com.microsoft.alm.storage.posix.internal.GnomeKeyringBackedSecureStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static com.microsoft.alm.helpers.LoggingHelper.logError;

public class GnomeKeyringBackedTokenPairStore extends GnomeKeyringBackedSecureStore<TokenPair> {

    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedTokenPairStore.class);

    @Override
    protected String serialize(final TokenPair tokenPair) {
        Debug.Assert(tokenPair != null, "TokenPair cannot be null");

        return toXmlString(tokenPair);
    }

    static String toXmlString(final TokenPair tokenPair) {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.newDocument();

            final Element element = tokenPair.toXml(document);
            document.appendChild(element);

            final String result = XmlHelper.toString(document);

            return result;
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    @Override
    protected TokenPair deserialize(final String secret) {
        Debug.Assert(secret != null, "secret cannot be null");

        try {
            return fromXmlString(secret);
        } catch (final Exception e) {
            logError(logger, "Failed to deserialize the stored secret. Return null.", e);
            return null;
        }
    }

    static TokenPair fromXmlString(final String xmlString) {
        final byte[] bytes = StringHelper.UTF8GetBytes(xmlString);
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        return fromXmlStream(inputStream);
    }

    static TokenPair fromXmlStream(final InputStream source) {
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
            final Document document = builder.parse(source);
            final Element rootElement = document.getDocumentElement();

            final TokenPair result = TokenPair.fromXml(rootElement);

            return result;
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    @Override
    protected String getType() {
        return "OAuth2Token";
    }
}
