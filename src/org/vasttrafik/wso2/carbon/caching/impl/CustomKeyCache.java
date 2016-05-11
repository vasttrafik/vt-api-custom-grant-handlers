package org.vasttrafik.wso2.carbon.caching.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;

public class CustomKeyCache
  extends CustomBaseCache<String, APIKeyValidationInfoDTO>
{
  private static Log log = LogFactory.getLog(CustomKeyCache.class);
  
  private static final String CUSTOM_KEY_CACHE_NAME = "CustomKeyCache";
  private static final int CUSTOM_KEY_CACHE_TIMEOUT = 3600;
  private static final int CUSTOM_KEY_CACHE_CAPACITY = 1000000;
  private static volatile CustomKeyCache instance;
  
  private CustomKeyCache()
  {
    super(CUSTOM_KEY_CACHE_NAME, CUSTOM_KEY_CACHE_TIMEOUT, CUSTOM_KEY_CACHE_CAPACITY);
  }
  
  public static CustomKeyCache getInstance()
  {
    
    if (instance == null) {
      synchronized (CustomKeyCache.class)
      {
        if (instance == null) {
          instance = new CustomKeyCache();
        }
      }
    }
    
    log.info("Custom key cache initiated with capacity: " + instance.getCapacity() + " and timeout: " + instance.getCacheTimeout());
    
    return instance;
  }
}
