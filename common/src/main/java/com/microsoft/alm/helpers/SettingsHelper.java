// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

/**
 * Utility class to read properties from a file.
 *
 * If the property is not found from the setting file, it will fallback to System properties.
 */
public class SettingsHelper {

    private static final Logger logger = LoggerFactory.getLogger(SettingsHelper.class);

    /**
     * Searching for TeamServices/auth_settings.properties file in the following folders.
     */
    private static Environment.SpecialFolder[] PARENT_FOLDERS = new Environment.SpecialFolder[] {
            Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolder.ApplicationData,
            Environment.SpecialFolder.UserProfile};

    private static String PROGRAM_FOLDER = SystemHelper.isWindows() ? "VSTeamServicesAuthPlugin" : ".VSTeamServicesAuthPlugin";
    private static String FILE_NAME = "settings.properties";

    private final Properties properties = new Properties();

    private static SettingsHelper instance;

    public static synchronized SettingsHelper getInstance() {
        if (instance == null) {
            instance = new SettingsHelper();
        }

        return instance;
    }

    private SettingsHelper() {
        // Trying to locate the settings file one by one
        for (final Environment.SpecialFolder candidate : PARENT_FOLDERS) {
            final String path = Environment.getFolderPath(candidate);
            final File folder = new File(path, PROGRAM_FOLDER);
            logger.info("Searching for {}", Path.combine(folder.getAbsolutePath(), FILE_NAME));
            if (folder.exists()) {
                final File potential = new File(folder, FILE_NAME);
                if (potential.exists() && potential.isFile() && potential.canRead()) {
                    logger.info("Found setting file, trying to load properties from {}", potential.getAbsolutePath());

                    try {
                        properties.load(new FileReader(potential));
                        logger.info("Properties loaded.");
                    } catch (Throwable t) {
                        logger.warn("Failed to load properties.", t);
                        properties.clear();
                    }

                    // Do not look further when we found a potential file
                    break;
                }
            }
        }
    }

    /**
     * Get named property.  Values from the setting files take precedence over System properties.
     * The method returns {@code null} if the property is not defined.
     *
     * @param name Property name
     * @return value of the property. {@code null} if property is not defined.
     */
    public synchronized String getProperty(final String name) {
        String result = properties.getProperty(name);
        if (result == null) {
            result = System.getProperty(name);
        }

        return result;
    }


    /**
     * Get named property.  Values from the setting files take precedence over System properties.
     *
     * If the property is not defined, return the default value.
     *
     * @param name Property name
     * @param defaultValue This value will be returned if property is not defined
     * @return value of the property, or the defaultValue.
     */
    public synchronized String getProperty(final String name, final String defaultValue) {
        final String result = getProperty(name);
        return result == null ? defaultValue : result;
    }
}
