package gov.nasa.jpl.ammos.asec.kmc.api.ex;

/**
 * KMC Exception
 */
public class KmcException extends Exception {

    /**
     * Constructor
     */
    public KmcException() {
        super();
    }

    /**
     * Constructor
     *
     * @param format format string
     */
    public KmcException(String format) {
        super(format);
    }

    /**
     * Constructor
     *
     * @param e Exception
     */
    public KmcException(Exception e) {
        super(e);
    }

    /**
     * Constructor
     *
     * @param message message
     * @param cause   cause
     */
    public KmcException(String message, Throwable cause) {
        super(message, cause);
    }
}
