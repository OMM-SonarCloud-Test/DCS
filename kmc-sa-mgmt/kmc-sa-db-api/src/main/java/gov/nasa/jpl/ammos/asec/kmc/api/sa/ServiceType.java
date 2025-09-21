package gov.nasa.jpl.ammos.asec.kmc.api.sa;

/**
 * Service type enum
 * <p>
 * For any combination of (Encryption, Authentication) service types,
 * PLAINTEXT = (0, 0)
 * ENCRYPTION = (1, 0)
 * AUTHENTICATION = (0, 1)
 * ENCRYPTION_AUTHENTICATION = (1, 1)
 */
public enum ServiceType {
    /**
     * Plaintext
     */
    PLAINTEXT((short) 0, (short) 0),
    /**
     * Encryption
     */
    ENCRYPTION((short) 1, (short) 0),
    /**
     * Authentication
     */
    AUTHENTICATION((short) 0, (short) 1),
    /**
     * Authenticated encryption
     */
    AUTHENTICATED_ENCRYPTION((short) 1, (short) 1),
    /**
     * Unknown
     */
    UNKNOWN((short) -1, (short) -1);

    private final Short enc;
    private final Short auth;

    /**
     * Constructor
     *
     * @param enc  encryption
     * @param auth authentication
     */
    ServiceType(Short enc, Short auth) {
        this.enc = enc;
        this.auth = auth;
    }

    /**
     * Convert from short int to service type
     *
     * @param serviceType short int
     * @return service type
     */
    public static ServiceType fromShort(Short serviceType) {
        if (serviceType == null) {
            return UNKNOWN;
        }
        switch (serviceType) {
            case 0:
                return PLAINTEXT;
            case 1:
                return ENCRYPTION;
            case 2:
                return AUTHENTICATION;
            case 3:
                return AUTHENTICATED_ENCRYPTION;
            default:
                return UNKNOWN;
        }
    }

    /**
     * Get service type from short ints
     *
     * @param enc  short int encryption
     * @param auth short int authentication
     * @return service type
     */
    public static ServiceType getServiceType(Short enc, Short auth) {
        if (enc == 0 && auth == 0) {
            return PLAINTEXT;
        } else if (enc == 1 && auth == 0) {
            return ENCRYPTION;
        } else if (enc == 0 && auth == 1) {
            return AUTHENTICATION;
        } else {
            return AUTHENTICATED_ENCRYPTION;
        }
    }

    /**
     * Get encryption type as short int
     *
     * @return short int encryption type
     */
    public Short getEncryptionType() {
        if (this == UNKNOWN) {
            return null;
        }
        return this.enc;
    }

    /**
     * Get authentication type as short int
     *
     * @return short int authentication type
     */
    public Short getAuthenticationType() {
        if (this == UNKNOWN) {
            return null;
        }
        return this.auth;
    }
}
