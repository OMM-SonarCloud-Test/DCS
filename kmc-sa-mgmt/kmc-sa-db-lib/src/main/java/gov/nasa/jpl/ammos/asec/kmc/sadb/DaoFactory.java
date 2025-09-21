package gov.nasa.jpl.ammos.asec.kmc.sadb;

import gov.nasa.jpl.ammos.asec.kmc.api.ex.KmcException;
import gov.nasa.jpl.ammos.asec.kmc.api.sadb.IKmcDao;
import gov.nasa.jpl.ammos.asec.kmc.sadb.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * KMC DAO provider
 */
public class DaoFactory {

    private static final Logger LOG = LoggerFactory.getLogger(DaoFactory.class);

    /**
     * Create and return a KMC DAO from config
     *
     * @param cfg config
     * @return KMC DAO
     * @throws KmcException kmc ex
     */
    public static IKmcDao getDao(Config cfg) throws KmcException {
        try {
            DaoBuilder builder = new DaoBuilder();
            if (cfg.getUseTls()) {
                if (cfg.getTruststore().equals(Config.NONE) || cfg.getTruststorePass().equals(Config.NONE)) {
                    throw new KmcException("When TLS is enabled, the " + "truststore and truststore password must be "
                            + "configured");
                }
                builder.useTls(cfg.getTruststore(), cfg.getTruststorePass(), cfg.getOverrideJvmTruststore());
            }

            if (cfg.getUseMtls()) {
                if (cfg.getKeystore().equals(Config.NONE) || cfg.getKeystorePass().equals(Config.NONE)) {
                    throw new KmcException("When TLS is enabled, the keystore " + "and keystore password must be " +
                            "configured");
                }
                builder.useMtls(cfg.getKeystore(), cfg.getKeystorePass());
            }

            if (!cfg.getConn().equals(Config.NONE)) {
                builder.setConnString(cfg.getConn());
            }

            if (!cfg.getHost().equals(Config.NONE)) {
                builder.setHost(cfg.getHost());
            } else {
                builder.setHost("localhost");
            }

            if (!cfg.getPort().equals(Config.NONE)) {
                builder.setPort(cfg.getPort());
            } else {
                builder.setPort("3306");
            }

            builder.setUser(cfg.getUser());

            if (!cfg.getPass().equals(Config.NONE)) {
                builder.setPass(cfg.getPass());
            } else {
                builder.setPass("");
            }

            builder.setSchema(cfg.getSchema());

            return builder.build();

        } catch (Exception e) {
            LOG.error("Error initializing application, please check database settings", e);
            throw new KmcException("Error initializing application, please check database settings", e);
        }
    }
}
