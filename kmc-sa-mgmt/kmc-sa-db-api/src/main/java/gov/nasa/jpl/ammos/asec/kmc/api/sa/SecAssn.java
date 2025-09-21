package gov.nasa.jpl.ammos.asec.kmc.api.sa;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/**
 * Security Assocation
 * <p>
 * // todo: move initial values to config
 */
@Entity(name = "SecAssn")
@Table(name = "security_associations")
public class SecAssn extends ASecAssn {
    /**
     * Constructor
     */
    public SecAssn() {
        this(new SpiScid());
    }

    /**
     * Constructor
     *
     * @param id SPI SCID
     */
    public SecAssn(SpiScid id) {
        super(id);
    }

    @Override
    public FrameType getType() {
        return FrameType.TC;
    }
}
