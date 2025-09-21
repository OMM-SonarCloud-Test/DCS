package gov.nasa.jpl.ammos.asec.kmc.api.sa;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/**
 * TM Security Association
 */
@Entity(name = "SecAssnTm")
@Table(name = "security_associations_tm")
public class SecAssnTm extends ASecAssn {
    /**
     * Constructor
     */
    public SecAssnTm() {
        this(new SpiScid());
    }

    /**
     * Constructor
     *
     * @param id SPI SCID
     */
    public SecAssnTm(SpiScid id) {
        super(id);
    }

    @Override
    public FrameType getType() {
        return FrameType.TM;
    }
}
