package org.vasttrafik.wso2.carbon.caching.shutdown;

import org.wso2.carbon.utils.ConfigurationContextService;

/**
* A singleton ConfigurationContext holder class to keep references to ConfigurationContextService.
*/
public class ConfigHolder {
 
   private ConfigurationContextService configurationContextService;
   private static final ConfigHolder configHolder = new ConfigHolder();
 
   private ConfigHolder() {
 
   }
 
   public static ConfigHolder getInstance() {
       return configHolder;
   }
   public ConfigurationContextService getConfigurationContextService() {
       return configurationContextService;
   }
 
   public void setConfigurationContextService(ConfigurationContextService configurationContextService) {
       this.configurationContextService = configurationContextService;
   }
}