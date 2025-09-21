package gov.nasa.jpl.ammos.asec.kmc.api.sa;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/**
 * AOS Security Association
 */
@Entity(name = "SecAssnAos")
@Table(name = "security_associations_aos")
public class SecAssnAos extends ASecAssn {
    /**
     * Constructor
     */
    public SecAssnAos() {
        this(new SpiScid());
    }

    /**
     * Constructor
     *
     * @param id SPI SCID
     */
    public SecAssnAos(SpiScid id) {
        super(id);
    }

    @Override
    public FrameType getType() {
        return FrameType.AOS;
    }
}
