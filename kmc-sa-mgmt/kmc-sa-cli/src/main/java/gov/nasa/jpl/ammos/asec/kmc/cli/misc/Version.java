package gov.nasa.jpl.ammos.asec.kmc.cli.misc;

import picocli.CommandLine;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Software version provider
 */
public class Version implements CommandLine.IVersionProvider {
    /**
     * Version file
     */
    private static final String     VERSION_FILE         = "version.properties";
    /**
     * Version property key
     */
    private static final String     VERSION_PROPERTY_KEY = "version";
    /**
     * Properties
     */
    private static final Properties properties           = loadProperties();
    /**
     * Version constant
     */
    private static final String     VERSION              = initializeVersion();

    private static Properties loadProperties() {
        Properties props = new Properties();
        try {
            InputStream stream = Version.class.getClassLoader().getResourceAsStream(VERSION_FILE);
            if (stream == null) {
                throw new IllegalStateException("Required resource '" + VERSION_FILE + "' not found in classpath");
            }
            try (stream) {
                props.load(stream);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load " + VERSION_FILE + ": " + e.getMessage(), e);
        }
        return props;
    }

    private static String initializeVersion() {
        String version = properties.getProperty(VERSION_PROPERTY_KEY);
        if (version == null || version.trim().isEmpty()) {
            throw new IllegalStateException("Version property not found in " + VERSION_FILE);
        }
        return version;
    }

    @Override
    public String[] getVersion() {
        return new String[]{VERSION};
    }
}
