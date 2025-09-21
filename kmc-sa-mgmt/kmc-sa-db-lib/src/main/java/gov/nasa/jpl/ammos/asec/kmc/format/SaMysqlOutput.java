package gov.nasa.jpl.ammos.asec.kmc.format;

import gov.nasa.jpl.ammos.asec.kmc.api.sa.ISecAssn;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;

import java.io.PrintWriter;
import java.util.List;

/**
 * Security Association output format that imitates the MySQL key-value format
 */
public class SaMysqlOutput implements IOutput {
    /**
     * Constructor
     */
    public SaMysqlOutput() {

    }

    @Override
    public void print(PrintWriter writer, List<ISecAssn> saList) {
        VelocityEngine engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        engine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
        engine.init();
        Template        t       = engine.getTemplate("templates/mysql.vm");
        VelocityContext context = new VelocityContext();
        context.put("Utilities", Utilities.class);
        context.put("saList", saList);
        t.merge(context, writer);
        writer.flush();
    }
}
