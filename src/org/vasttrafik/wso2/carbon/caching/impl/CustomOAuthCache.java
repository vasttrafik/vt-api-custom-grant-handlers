package org.vasttrafik.wso2.carbon.caching.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.vasttrafik.wso2.carbon.caching.impl.eviction.NoneEvictionAlgorithm;

import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;

public class CustomOAuthCache
  extends CustomBaseCache<OAuthCacheKey, CacheEntry>
{
  @SuppressWarnings("unused")
  private static Log log = LogFactory.getLog(CustomOAuthCache.class);
  
  private static final String CUSTOM_OAUTH_CACHE_NAME = "CustomOAuthCache";
  private static final int CUSTOM_OAUTH_CACHE_TIMEOUT = 900;
  private static final int CUSTOM_OAUTH_CACHE_CAPACITY = 1000000;
  private static volatile CustomOAuthCache instance;
  
  private CustomOAuthCache()
  {
    super(CUSTOM_OAUTH_CACHE_NAME, CUSTOM_OAUTH_CACHE_TIMEOUT, CUSTOM_OAUTH_CACHE_CAPACITY, new NoneEvictionAlgorithm());
  }
  
  public static CustomOAuthCache getInstance()
  {
    
    if (instance == null) {
      synchronized (CustomOAuthCache.class)
      {
        if (instance == null) {
          instance = new CustomOAuthCache();
        }
      }
    }
    
    return instance;
  }
}
