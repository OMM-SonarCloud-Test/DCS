package gov.nasa.jpl.ammos.asec.kmc.saserver.app;


import jakarta.annotation.PostConstruct;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;

import java.util.Arrays;
import java.util.Properties;
import java.util.stream.StreamSupport;

@Configuration
@PropertySource("classpath:kmc-sa-mgmt-service.properties")
public class KmcSaMgmtServiceConfiguration implements EnvironmentAware {

    static Environment springEnv;

    @Override
    public void setEnvironment(Environment environment) {
        KmcSaMgmtServiceConfiguration.springEnv = environment;
    }

    public KmcSaMgmtServiceConfiguration() {
    }

    @PostConstruct
    public Properties getConfiguration() {
        Properties             props    = new Properties();
        MutablePropertySources propSrcs = ((AbstractEnvironment) springEnv).getPropertySources();
        StreamSupport.stream(propSrcs.spliterator(), false)
                .filter(ps -> ps instanceof EnumerablePropertySource)
                .map(ps -> ((EnumerablePropertySource) ps).getPropertyNames())
                .flatMap(Arrays::<String>stream)
                .forEach(propName -> props.setProperty(propName, springEnv.getProperty(propName)));

        return props;
    }

}
