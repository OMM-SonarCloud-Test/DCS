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
 * CSV Output Formatter
 */
public class SaCsvOutput implements IOutput {

    /**
     * Extended output template
     */
    public static final String  TEMPLATES_EXTENDED_VM  = "templates/extended.vm";
    /**
     * Condensed output template
     */
    public static final String  TEMPLATES_CONDENSED_VM = "templates/condensed.vm";
    private final       boolean extended;

    /**
     * Constructor
     *
     * @param extended if enabled, outputs a more verbose CSV table
     */
    public SaCsvOutput(boolean extended) {
        this.extended = extended;
    }

    @Override
    public void print(PrintWriter writer, List<ISecAssn> sas) {
        VelocityEngine engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        engine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
        engine.init();
        Template t;
        if (extended) {
            t = engine.getTemplate(TEMPLATES_EXTENDED_VM);
        } else {
            t = engine.getTemplate(TEMPLATES_CONDENSED_VM);
        }
        VelocityContext context = new VelocityContext();
        context.put("Utilities", Utilities.class);
        context.put("saList", sas);
        t.merge(context, writer);
        writer.flush();
    }
}

