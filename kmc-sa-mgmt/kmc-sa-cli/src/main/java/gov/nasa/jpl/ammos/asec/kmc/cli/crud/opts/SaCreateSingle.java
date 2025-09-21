package gov.nasa.jpl.ammos.asec.kmc.cli.crud.opts;

import picocli.CommandLine;

/**
 * SA single record creation opts
 */
@CommandLine.Command
public class SaCreateSingle {
    /**
     * TFVN opt
     */
    @CommandLine.Option(names = "--tfvn", required = true, description = "transfer frame version number")
    public Byte tfvn;

    /**
     * SCID opt
     */
    @CommandLine.Option(names = "--scid", required = true, description = "spacecraft ID")
    public Short scid;

    /**
     * VCID opt
     */
    @CommandLine.Option(names = "--vcid", required = true, description = "virtual channel ID")
    public Byte vcid;

    /**
     * MAPID opt
     */
    @CommandLine.Option(names = "--mapid", required = true, description = "multiplexer access ID")
    public Byte mapid;

    /**
     * SPI opt
     */
    @CommandLine.Option(names = "--spi", required = false, description = "security parameter index")
    public Integer spi;
}
