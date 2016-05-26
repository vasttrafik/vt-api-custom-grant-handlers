package org.vasttrafik.wso2.carbon.caching.shutdown;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.core.ServerShutdownHandler;
import org.wso2.carbon.utils.ConfigurationContextService;

/**
* This service component register a CustomAccessTokenCacheShutdownManager as 
* a ServerShutdownHandler.
*/
@Component(name = "vasttrafik.core.services.custom.cache.shutdowncomponent", immediate = true)
public class ShutdownServiceComponent {
   private static Log log = LogFactory.getLog(ShutdownServiceComponent.class);
   private static BundleContext bundleContext;
   
   @Activate
   protected void activate(ComponentContext context) {
	   log.info("*******  CustomAccessTokenCacheShutdownComponent activated  *******");
       bundleContext = context.getBundleContext();
       bundleContext.registerService(ServerShutdownHandler.class.getName(), new CustomAccessTokenCacheShutdownManager(), null);
   }
 
   @Reference (name = "custom.cache.config.service",
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               service = org.wso2.carbon.utils.ConfigurationContextService.class,
               unbind = "unsetConfigurationContextService")
   protected void setConfigurationContextService(ConfigurationContextService configurationContextService) {
       log.debug("******* ConfigurationContextService  is set ******* ");
       ConfigHolder.getInstance().setConfigurationContextService(configurationContextService);
   }
 
   protected void unsetConfigurationContextService(ConfigurationContextService configurationContextService) {
       log.debug("******* ConfigurationContextService is unset ******* ");
   }
 
   protected void deactivate(ComponentContext context) {
       ShutdownServiceComponent.bundleContext = null;
       log.debug("CustomAccessTokenCacheShutdownComponent deactivated ");
   }

}
