package org.vasttrafik.wso2.carbon.caching.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

public class CustomAccessTokenCache
  extends CustomBaseCache<String, AccessTokenDO>
{
  private static Log log = LogFactory.getLog(CustomAccessTokenCache.class);
  
  private static final String CUSTOM_ACCESS_TOKEN_CACHE_NAME = "CustomAccessTokenCache";
  private static final int CUSTOM_ACCESS_TOKEN_CACHE_TIMEOUT = 18000; // 5 hours
  private static final int CUSTOM_ACCESS_TOKEN_CACHE_CAPACITY = 1000000;
  private static volatile CustomAccessTokenCache instance;
  
  private CustomAccessTokenCache()
  {
    super(CUSTOM_ACCESS_TOKEN_CACHE_NAME, CUSTOM_ACCESS_TOKEN_CACHE_TIMEOUT, CUSTOM_ACCESS_TOKEN_CACHE_CAPACITY);
  }
  
  public static CustomAccessTokenCache getInstance()
  {
    
    if (instance == null) {
      synchronized (CustomAccessTokenCache.class)
      {
        if (instance == null) {
          instance = new CustomAccessTokenCache();
        }
      }
    }
    
    log.info("Custom access token cache initiated with capacity: " + instance.getCapacity() + " and timeout: " + instance.getCacheTimeout());
    
    return instance;
  }
}
