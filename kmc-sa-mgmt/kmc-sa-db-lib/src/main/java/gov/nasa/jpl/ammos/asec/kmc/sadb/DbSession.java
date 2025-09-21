package gov.nasa.jpl.ammos.asec.kmc.sadb;

import gov.nasa.jpl.ammos.asec.kmc.api.ex.KmcException;
import gov.nasa.jpl.ammos.asec.kmc.api.sadb.IDbSession;
import jakarta.persistence.PersistenceException;
import org.hibernate.Session;
import org.hibernate.Transaction;

/**
 * Database session implementation against Hibernate
 */
public class DbSession implements IDbSession {
    private final Session     session;
    private       Transaction tx;

    /**
     * Constructor
     *
     * @param session session
     */
    public DbSession(Session session) {
        this.session = session;
    }

    @Override
    public boolean isActive() {
        return tx != null && tx.isActive();
    }

    @Override
    public void close() throws Exception {
        session.close();
    }

    @Override
    public void beginTransaction() {
        tx = session.beginTransaction();
    }

    @Override
    public void validate() throws KmcException {
        if (tx == null || !tx.isActive()) {
            throw new KmcException("No valid transaction");
        }
    }

    @Override
    public void commit() throws KmcException {
        validate();
        try {
            tx.commit();
        } catch (Exception e) {
            throw new KmcException(e);
        }
    }

    @Override
    public void rollback() throws KmcException {
        validate();
        try {
            tx.rollback();
        } catch (IllegalStateException | PersistenceException exception) {
            throw new KmcException(exception);
        }
    }

    @Override
    public void persist(Object o) throws KmcException {
        session.persist(o);
    }

    @Override
    public void merge(Object o) throws KmcException {
        session.merge(o);
    }

    @Override
    public void remove(Object o) throws KmcException {
        session.remove(o);
    }

    /**
     * Get session
     *
     * @return session
     */
    protected Session getSession() {
        return session;
    }

    @Override
    public void flush() {
        session.flush();
    }
}
