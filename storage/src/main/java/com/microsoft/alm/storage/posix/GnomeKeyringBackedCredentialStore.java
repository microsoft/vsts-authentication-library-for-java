// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage.posix;

import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.StringHelper;
import com.microsoft.alm.helpers.XmlHelper;
import com.microsoft.alm.secret.Credential;
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

public class GnomeKeyringBackedCredentialStore extends GnomeKeyringBackedSecureStore<Credential> {

    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedCredentialStore.class);

    @Override
    protected Credential deserialize(final String secret) {
        Debug.Assert(secret != null, "secret cannot be null");

        try {
            return fromXmlString(secret);
        } catch (final Exception e) {
            logError(logger, "Failed to deserialize credential.", e);
            return null;
        }
    }

    static Credential fromXmlString(final String xmlString) {
        final byte[] bytes = StringHelper.UTF8GetBytes(xmlString);
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        return fromXmlStream(inputStream);
    }

    static Credential fromXmlStream(final InputStream source) {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.parse(source);
            final Element rootElement = document.getDocumentElement();

            final Credential result = XmlHelper.fromXmlToCredential(rootElement);

            return result;
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    @Override
    protected String serialize(final Credential credential) {
        Debug.Assert(credential != null, "Credential cannot be null");

        return toXmlString(credential);
    }

    static String toXmlString(final Credential credential) {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.newDocument();

            final Element element = XmlHelper.toXml(document, credential);
            document.appendChild(element);

            final String result = XmlHelper.toString(document);

            return result;
        }
        catch (final Exception e) {
            throw new Error(e);
        }

    }

    @Override
    protected String getType() {
        return "Credential";
    }
}
