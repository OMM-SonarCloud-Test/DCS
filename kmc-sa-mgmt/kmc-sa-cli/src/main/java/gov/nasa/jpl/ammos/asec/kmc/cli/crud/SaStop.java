package gov.nasa.jpl.ammos.asec.kmc.cli.crud;

import gov.nasa.jpl.ammos.asec.kmc.api.ex.KmcException;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.SpiScid;
import gov.nasa.jpl.ammos.asec.kmc.api.sadb.IKmcDao;
import gov.nasa.jpl.ammos.asec.kmc.cli.misc.Version;
import picocli.CommandLine;

/**
 * Stop security associations
 */
@CommandLine.Command(name = "stop", description = "Stop a Security Association", mixinStandardHelpOptions = true,
        versionProvider = Version.class)
public class SaStop extends BaseCliApp {
    @CommandLine.Option(names = {"-f",
            "--force"}, description = "Force an SA to start, if another SA is currently active.")
    private boolean force = false;

    @CommandLine.Option(names = "--scid", required = true, description = "spacecraft ID")
    private Short     scid;
    @CommandLine.Option(names = "--spi", required = true, description = "security parameter index")
    private Integer[] spi;

    @Override
    public Integer call() throws KmcException {
        int exit = 0;
        try (IKmcDao dao = getDao()) {
            for (Integer s : spi) {
                try {
                    dao.stopSa(new SpiScid(s, scid), frameType);
                    console(String.format("%s stopped SA %d/%d", System.getProperty("user.name"), s, scid));
                } catch (KmcException e) {
                    warn(String.format("%s, skipping stop on SA %d/%d", e.getMessage(), s, scid));
                    exit = 1;
                }
            }
        }

        return exit;
    }

    /**
     * Main
     *
     * @param args args
     */
    public static void main(String... args) {
        int exit = new CommandLine(new SaStop()).execute(args);
        System.exit(exit);
    }
}
