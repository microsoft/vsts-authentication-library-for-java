// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.storage;

import com.microsoft.alm.common.helpers.Environment;
import com.microsoft.alm.common.helpers.IOHelper;
import com.microsoft.alm.common.helpers.SystemHelper;
import com.microsoft.alm.common.helpers.XmlHelper;
import com.microsoft.alm.common.secret.Credential;
import com.microsoft.alm.common.secret.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import static com.microsoft.alm.common.helpers.LoggingHelper.logError;

class InsecureFileBackend {

    private static final Logger logger = LoggerFactory.getLogger(InsecureFileBackend.class);

    public static final String PROGRAM_FOLDER_NAME = "VSTeamServicesAuthPlugin";

    private final File backingFile;

    final Map<String, Token> Tokens = new HashMap<String, Token>();
    final Map<String, Credential> Credentials = new HashMap<String, Credential>();

    private static InsecureFileBackend instance;

    public static synchronized InsecureFileBackend getInstance() {
        if (instance == null) {
            instance = new InsecureFileBackend(getBackingFile());
        }

        return instance;
    }

    /**
     * Creates an instance that reads from and writes to the specified backingFile.
     *
     * @param backingFile the file to read from and write to.  Does not need to exist first.
     */
    InsecureFileBackend(final File backingFile) {
        this.backingFile = backingFile;
        reload();
    }

    void reload() {
        if (backingFile != null && backingFile.isFile() && backingFile.length() > 0) {
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(backingFile);
                final InsecureFileBackend clone = fromXml(fis);
                if (clone != null) {
                    this.Tokens.clear();
                    this.Tokens.putAll(clone.Tokens);

                    this.Credentials.clear();
                    this.Credentials.putAll(clone.Credentials);
                }
            } catch (final FileNotFoundException e) {
                logger.info("backingFile {} did not exist", backingFile.getAbsolutePath());
            } finally {
                IOHelper.closeQuietly(fis);
            }
        }
    }

    void save() {
        if (backingFile != null) {
            // TODO: 449510: consider creating a backup of the file, if it exists, before overwriting it
            FileOutputStream fos = null;
            try {
                fos = new FileOutputStream(backingFile);
                toXml(fos);
            } catch (final FileNotFoundException e) {
                throw new Error("Error during save()", e);
            } finally {
                IOHelper.closeQuietly(fos);
            }

            if (!backingFile.setReadable(false, false)
                    || !backingFile.setWritable(false, false)
                    || !backingFile.setExecutable(false, false)) {
                logger.warn("Unable to remove file permissions for everybody: {}", backingFile);
            }
            if (!backingFile.setReadable(true, true)
                    || !backingFile.setWritable(true, true)
                    || !backingFile.setExecutable(false, true)) {
                logger.warn("Unable to set file permissions for owner: {}", backingFile);
            }
        }
    }

    static InsecureFileBackend fromXml(final InputStream source) {
        try {
            final InsecureFileBackend result = new InsecureFileBackend(null);
            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.parse(source);
            final Element insecureStoreElement = document.getDocumentElement();

            final NodeList tokensOrCredentialsList = insecureStoreElement.getChildNodes();
            for (int toc = 0; toc < tokensOrCredentialsList.getLength(); toc++) {
                final Node tokensOrCredentials = tokensOrCredentialsList.item(toc);
                if (tokensOrCredentials.getNodeType() != Node.ELEMENT_NODE)
                    continue;
                if ("Tokens".equals(tokensOrCredentials.getNodeName())) {
                    result.Tokens.clear();
                } else if ("Credentials".equals(tokensOrCredentials.getNodeName())) {
                    result.Credentials.clear();
                } else continue;
                final NodeList entryList = tokensOrCredentials.getChildNodes();
                for (int e = 0; e < entryList.getLength(); e++) {
                    final Node entryNode = entryList.item(e);
                    if (entryNode.getNodeType() != Node.ELEMENT_NODE || !"entry".equals(entryNode.getNodeName()))
                        continue;
                    if ("Tokens".equals(tokensOrCredentials.getNodeName())) {
                        loadToken(result, entryNode);
                    } else if ("Credentials".equals(tokensOrCredentials.getNodeName())) {
                        loadCredential(result, entryNode);
                    }
                }
            }
            return result;
        } catch (final Exception e) {
            logError(logger, "Warning: unable to deserialize InsecureFileBackend. Is the file corrupted?", e);
            return null;
        }
    }

    private static void loadCredential(final InsecureFileBackend result, final Node entryNode) {
        String key = null;
        Credential value = null;
        final NodeList keyOrValueList = entryNode.getChildNodes();
        for (int kov = 0; kov < keyOrValueList.getLength(); kov++) {
            final Node keyOrValueNode = keyOrValueList.item(kov);
            if (keyOrValueNode.getNodeType() != Node.ELEMENT_NODE) continue;

            final String keyOrValueName = keyOrValueNode.getNodeName();
            if ("key".equals(keyOrValueName)) {
                key = XmlHelper.getText(keyOrValueNode);
            } else if ("value".equals(keyOrValueName)) {
                value = Credential.fromXml(keyOrValueNode);
            }
        }
        result.Credentials.put(key, value);
    }

    private static void loadToken(final InsecureFileBackend result, final Node entryNode) {
        String key = null;
        Token value = null;
        final NodeList keyOrValueList = entryNode.getChildNodes();
        for (int kov = 0; kov < keyOrValueList.getLength(); kov++) {
            final Node keyOrValueNode = keyOrValueList.item(kov);
            if (keyOrValueNode.getNodeType() != Node.ELEMENT_NODE) continue;
            final String keyOrValueName = keyOrValueNode.getNodeName();
            if ("key".equals(keyOrValueName)) {
                key = XmlHelper.getText(keyOrValueNode);
            } else if ("value".equals(keyOrValueName)) {
                value = Token.fromXml(keyOrValueNode);
            }
        }
        result.Tokens.put(key, value);
    }

    void toXml(final OutputStream destination) {
        try {
            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.newDocument();

            final Element insecureStoreNode = document.createElement("insecureStore");
            insecureStoreNode.appendChild(createTokensNode(document));
            insecureStoreNode.appendChild(createCredentialsNode(document));
            document.appendChild(insecureStoreNode);

            final TransformerFactory tf = TransformerFactory.newInstance();
            final Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
            //http://johnsonsolutions.blogspot.ca/2007/08/xml-transformer-indent-doesnt-work-with.html
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new DOMSource(document), new StreamResult(destination));
        } catch (final Exception e) {
            throw new Error(e);
        }
    }

    private Element createTokensNode(final Document document) {
        final Element tokensNode = document.createElement("Tokens");
        for (final Map.Entry<String, Token> entry : Tokens.entrySet()) {
            final Element entryNode = document.createElement("entry");

            final Element keyNode = document.createElement("key");
            final Text keyValue = document.createTextNode(entry.getKey());
            keyNode.appendChild(keyValue);
            entryNode.appendChild(keyNode);

            final Token value = entry.getValue();
            if (value != null) {
                final Element valueNode = value.toXml(document);

                entryNode.appendChild(valueNode);
            }

            tokensNode.appendChild(entryNode);
        }
        return tokensNode;
    }

    private Element createCredentialsNode(final Document document) {
        final Element credentialsNode = document.createElement("Credentials");
        for (final Map.Entry<String, Credential> entry : Credentials.entrySet()) {
            final Element entryNode = document.createElement("entry");

            final Element keyNode = document.createElement("key");
            final Text keyValue = document.createTextNode(entry.getKey());
            keyNode.appendChild(keyValue);
            entryNode.appendChild(keyNode);

            final Credential value = entry.getValue();
            if (value != null) {
                final Element valueNode = value.toXml(document);

                entryNode.appendChild(valueNode);
            }
            credentialsNode.appendChild(entryNode);
        }
        return credentialsNode;
    }

    public synchronized boolean delete(final String targetName) {
        if (Tokens.containsKey(targetName)) {
            Tokens.remove(targetName);
            save();
        } else if (Credentials.containsKey(targetName)) {
            Credentials.remove(targetName);
            save();
        }

        return true;
    }

    public synchronized Credential readCredentials(final String targetName) {
        return Credentials.get(targetName);
    }

    public synchronized Token readToken(final String targetName) {
        return Tokens.get(targetName);
    }

    public synchronized void writeCredential(final String targetName, final Credential credentials) {
        Credentials.put(targetName, credentials);
        save();
    }

    public synchronized void writeToken(final String targetName, final Token token) {
        Tokens.put(targetName, token);
        save();
    }

    private static File getBackingFile() {
        final File parentFolder = determineParentFolder();

        // .hidden this folder on *nix system
        final String programFolderName = SystemHelper.isWindows() ? PROGRAM_FOLDER_NAME : "." + PROGRAM_FOLDER_NAME;
        final File programFolder = new File(parentFolder, programFolderName);

        if (!programFolder.exists()) {
            programFolder.mkdirs();
        }

        final File insecureFile = new File(programFolder, "insecureStore.xml");

        return insecureFile;
    }

    private static File determineParentFolder() {
        return findFirstValidFolder(
                Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolder.ApplicationData,
                Environment.SpecialFolder.UserProfile);
    }

    private static File findFirstValidFolder(final Environment.SpecialFolder... candidates) {
        for (final Environment.SpecialFolder candidate : candidates) {
            final String path = Environment.getFolderPath(candidate);
            if (path == null)
                continue;
            final File result = new File(path);
            if (result.isDirectory()) {
                return result;
            }
        }
        final String path = System.getenv("HOME");
        final File result = new File(path);
        return result;
    }
}
