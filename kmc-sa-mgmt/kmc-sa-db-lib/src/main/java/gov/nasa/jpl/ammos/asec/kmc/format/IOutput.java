package gov.nasa.jpl.ammos.asec.kmc.format;

import gov.nasa.jpl.ammos.asec.kmc.api.sa.ISecAssn;

import java.io.PrintWriter;
import java.util.List;

/**
 * Security Association output interface
 */
public interface IOutput {

    /**
     * Print SA output to a writer
     *
     * @param writer output
     * @param saList list of security associations
     */
    void print(PrintWriter writer, List<ISecAssn> saList);
}
