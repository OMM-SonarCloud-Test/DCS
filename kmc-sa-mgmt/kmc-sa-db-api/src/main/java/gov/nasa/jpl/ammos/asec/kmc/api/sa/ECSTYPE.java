package gov.nasa.jpl.ammos.asec.kmc.api.sa;

import java.util.Arrays;
import java.util.Optional;

/**
 * Enum used to store every valid ECS. Currently used only in validation, but could (and maybe should) be used for
 * general ecs storage
 */
public enum ECSTYPE {
    /**
     * AES GCM
     */
    AES_GCM(new byte[]{0x01}, (short) 12),
    /**
     * AES CBC
     */
    AES_CBC(new byte[]{0x02}, (short) 16);


    private final byte[] value;
    private final int    ivLen;

    /**
     * constructor
     *
     * @param value ECS type byte value
     * @param ivLen IV length
     */
    ECSTYPE(final byte[] value, final short ivLen) {
        this.value = Arrays.copyOf(value, value.length);
        this.ivLen = ivLen;
    }

    /**
     * Return the specific enum for a given bytes, or NULL if it can't be found
     *
     * @param value ECS bytes
     * @return ECS type
     */
    public static ECSTYPE fromBytes(byte[] value) {
        Optional<ECSTYPE> result =
                Arrays.stream(ECSTYPE.class.getEnumConstants()).filter(ecs -> Arrays.equals(ecs.value, value)).findFirst();
        if (result.isPresent()) {
            return result.get();
        } else {
            return null;
        }
    }

    /**
     * Check if a given IV length would be acceptable for this ECS. Currently just a check of the ivLen field.
     *
     * @param proposedIvLen proposed IV length
     * @return valid or invalid
     */
    public boolean validIvLen(short proposedIvLen) {
        return proposedIvLen == this.ivLen;
    }

    /**
     * @return IV length
     */
    public int getIvLen() {
        return ivLen;
    }

    /**
     * @return value
     */
    public byte[] getValue() {
        return Arrays.copyOf(value, value.length);
    }
}
