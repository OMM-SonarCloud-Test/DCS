package gov.nasa.jpl.ammos.asec.kmc.cli.opts;

import picocli.CommandLine;

/**
 * Key opts
 */
public class KeyOpts {
    /**
     * EKID opt
     */
    @CommandLine.Option(names = "--ekid", required = false, description = "encryption key ID")
    public String ekid;

    /**
     * ECS opt
     */
    @CommandLine.Option(names = "--ecs", required = false, description = "encryption cypher suite (hex string)")
    public String ecs;

    /**
     * ECS length opt
     */
    @CommandLine.Option(names = "--ecslen", required = false, description = "ecs byte length")
    public Short ecsLen;

    /**
     * AKID opt
     */
    @CommandLine.Option(names = "--akid", required = false, description = "authentication key ID")
    public String akid;

    /**
     * ACS opt
     */
    @CommandLine.Option(names = "--acs", required = false, description = "authentication cypher suite")
    public String acs;

    /**
     * ACS length opt
     */
    @CommandLine.Option(names = "--acslen", required = false, description = "acs length (bytes)")
    public Short acsLen;
}
