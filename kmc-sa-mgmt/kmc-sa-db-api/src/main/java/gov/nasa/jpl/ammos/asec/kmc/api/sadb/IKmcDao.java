package gov.nasa.jpl.ammos.asec.kmc.api.sadb;

import gov.nasa.jpl.ammos.asec.kmc.api.ex.KmcException;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.FrameType;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.ISecAssn;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.SpiScid;

import java.util.List;

/**
 * KMC DAO
 */
public interface IKmcDao extends AutoCloseable {

    /**
     * Get a New DB session
     *
     * @return DB session
     */
    IDbSession newSession();

    /**
     * Create an SA with provided database session. Initial state is UNKEYED.
     *
     * @param IdbSession database session
     * @param spi        security parameter index
     * @param tvfn       transfer frame version number
     * @param scid       spacecraft id
     * @param vcid       virtual channel id
     * @param mapid      multiplexer access point id
     * @param type       frame type
     * @throws KmcException exception
     */
    void createSa(IDbSession IdbSession, Integer spi, Byte tvfn, Short scid, Byte vcid, Byte mapid, FrameType type) throws KmcException;

    /**
     * Create an SA. Initial state is UNKEYED.
     *
     * @param spi   security parameter index
     * @param tvfn  transfer frame version number
     * @param scid  spacecraft id
     * @param vcid  virtual channel id
     * @param mapid multiplexer access point id
     * @param type  frame type
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn createSa(Integer spi, Byte tvfn, Short scid, Byte vcid, Byte mapid, FrameType type) throws KmcException;

    /**
     * Create an SA
     *
     * @param sa security association
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn createSa(ISecAssn sa) throws KmcException;

    /**
     * Create an SA with the provided DB session
     *
     * @param IdbSession database session
     * @param sa         security association
     * @throws KmcException exception
     */
    void createSa(IDbSession IdbSession, ISecAssn sa) throws KmcException;

    /**
     * Re/key an SA for encryption with the provided database session
     *
     * @param session database session
     * @param id      spi + scid
     * @param ekid    encryption key id
     * @param ecs     encryption cipher suite
     * @param ecsLen  ecs length
     * @param type    frame type
     * @throws KmcException exception
     */
    void rekeySaEnc(IDbSession session, SpiScid id, String ekid, byte[] ecs, Short ecsLen, FrameType type) throws KmcException;

    /**
     * Re/key an SA for encryption
     *
     * @param id     spi + scid
     * @param ekid   encryption key id
     * @param ecs    encryption cipher suite
     * @param ecsLen ecs length
     * @param type   frame type
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn rekeySaEnc(SpiScid id, String ekid, byte[] ecs, Short ecsLen, FrameType type) throws KmcException;

    /**
     * Rekey an SA for authentication with the provided database session
     *
     * @param session database session
     * @param id      spi + scid
     * @param akid    authentication key id
     * @param acs     authentication cipher suite
     * @param acsLen  acs length
     * @param type    frame type
     * @throws KmcException exception
     */
    void rekeySaAuth(IDbSession session, SpiScid id, String akid, byte[] acs, Short acsLen, FrameType type) throws KmcException;

    /**
     * Rekey an SA for authentication
     *
     * @param id     spi + scid
     * @param akid   authentication key id
     * @param acs    authentication cipher suite
     * @param acsLen acs length
     * @param type   frame type
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn rekeySaAuth(SpiScid id, String akid, byte[] acs, Short acsLen, FrameType type) throws KmcException;

    /**
     * Expire an SA with the provided database session
     *
     * @param session database session
     * @param id      spi + scid
     * @param type    frame type
     * @throws KmcException exception
     */
    void expireSa(IDbSession session, SpiScid id, FrameType type) throws KmcException;

    /**
     * Expire an SA
     *
     * @param id   spi + scid
     * @param type frame type
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn expireSa(SpiScid id, FrameType type) throws KmcException;

    /**
     * Start an SA with the provided database session. Sets given SPI SA to ENABLED, all other SAs to KEYED.
     *
     * @param session database session
     * @param id      spi + scid
     * @param force   start SA, stopping other SAs with same GVCID
     * @param type    frame type
     * @throws KmcException exception
     */
    void startSa(IDbSession session, SpiScid id, boolean force, FrameType type) throws KmcException;

    /**
     * Start an SA. Sets given SPI SA to ENABLED, all other SAs to KEYED.
     *
     * @param id    spi + scid
     * @param force start SA, stopping other SAs with same GVCID
     * @param type  frame type
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn startSa(SpiScid id, boolean force, FrameType type) throws KmcException;

    /**
     * Stop an SA with the provided database session. Sets given SPI SA to KEYED.
     *
     * @param session database session
     * @param id      spi + scid
     * @param type    frame type
     * @throws KmcException exception
     */
    void stopSa(IDbSession session, SpiScid id, FrameType type) throws KmcException;

    /**
     * Stop an SA. Sets given SPI SA to KEYED.
     *
     * @param id   spi + scid
     * @param type frame type
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn stopSa(SpiScid id, FrameType type) throws KmcException;

    /**
     * Delete an SA with the provided database session. Removes the SA from the DB.
     *
     * @param session database session
     * @param id      spi + scid
     * @param type    frame type
     * @throws KmcException exception
     */
    void deleteSa(IDbSession session, SpiScid id, FrameType type) throws KmcException;

    /**
     * Delete an SA. Removes the SA from the DB.
     *
     * @param id   spi + scid
     * @param type frame type
     * @throws KmcException exception
     */
    void deleteSa(SpiScid id, FrameType type) throws KmcException;

    /**
     * Get an SA with the provided database session
     *
     * @param session database session
     * @param id      spi + scid
     * @param type    frame type
     * @return security association
     * @throws KmcException exception
     */
    ISecAssn getSa(IDbSession session, SpiScid id, FrameType type) throws KmcException;

    /**
     * Get an SA
     *
     * @param id   spi + scid
     * @param type frame type
     * @return security association
     * @throws KmcException exception
     */
    ISecAssn getSa(SpiScid id, FrameType type) throws KmcException;

    /**
     * Get all SAs with the provided database session
     *
     * @param session database session
     * @param type    frame type
     * @return a list of SAs
     * @throws KmcException exception
     */
    List<ISecAssn> getSas(IDbSession session, FrameType type) throws KmcException;

    /**
     * Get all SAs
     *
     * @param type frame type
     * @return a list of SAs
     * @throws KmcException exception
     */
    List<ISecAssn> getSas(FrameType type) throws KmcException;

    /**
     * Update an SA with the provided database session
     *
     * @param session database session
     * @param sa      security association
     * @throws KmcException exception
     */
    void updateSa(IDbSession session, ISecAssn sa) throws KmcException;

    /**
     * Update an SA
     *
     * @param sa security association
     * @return sa
     * @throws KmcException exception
     */
    ISecAssn updateSa(ISecAssn sa) throws KmcException;

    /**
     * Close the DAO
     *
     * @throws KmcException exception
     */
    void close() throws KmcException;

    /**
     * Initialize the DAO
     *
     * @throws KmcException exception
     */
    void init() throws KmcException;

    /**
     * Returns operational status
     *
     * @return true if operational, false if not
     */
    boolean status();
}
