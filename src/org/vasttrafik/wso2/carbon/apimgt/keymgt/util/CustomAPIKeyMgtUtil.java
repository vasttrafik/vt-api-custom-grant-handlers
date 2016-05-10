package org.vasttrafik.wso2.carbon.apimgt.keymgt.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.caching.impl.CacheImpl;

import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;
import java.util.concurrent.TimeUnit;

public class CustomAPIKeyMgtUtil {

  private static final Log log = LogFactory.getLog(CustomAPIKeyMgtUtil.class);
  
  private  static boolean isCustomKeyCacheInitialized = false;

  /**
   * Get the KeyValidationInfo object from cache, for a given cache-Key
   *
   * @param cacheKey Key for the Cache Entry
   * @return APIKeyValidationInfoDTO
   * @throws APIKeyMgtException
   */
  public static APIKeyValidationInfoDTO getFromKeyManagerCache(String cacheKey) {

    APIKeyValidationInfoDTO info = null;

    Cache<String, APIKeyValidationInfoDTO> cache = getCustomKeyManagerCache();

    info = (APIKeyValidationInfoDTO) cache.get(cacheKey);
    // If key validation information is not null then only we proceed with cached object
    if (info != null) {
      if (log.isDebugEnabled()) {
        log.debug("Found cached access token for : " + cacheKey + ".");
      }
    }

    return info;
  }


  /**
   * Store KeyValidationInfoDTO in Key Manager Cache
   *
   * @param cacheKey Key for the Cache Entry to be stored
   * @param validationInfoDTO KeyValidationInfoDTO object
   */
  public static void writeToKeyManagerCache(String cacheKey, APIKeyValidationInfoDTO validationInfoDTO) {

    if (cacheKey != null) {
      if (log.isDebugEnabled()) {
        log.debug("Storing KeyValidationDTO for key: " + cacheKey + ".");
      }
    }

    if (validationInfoDTO != null) {
        Cache<String, APIKeyValidationInfoDTO> cache = getCustomKeyManagerCache();
        cache.put(cacheKey, validationInfoDTO);
    }
  }

  /**
   * Remove APIKeyValidationInfoDTO from Key Manager Cache
   *
   * @param cacheKey Key for the Cache Entry to be removed
   */
  public static void removeFromCustomKeyManagerCache(String cacheKey) {

    if (cacheKey != null) {
      Cache<String, APIKeyValidationInfoDTO> cache = getCustomKeyManagerCache();
      cache.remove(cacheKey);
      log.debug("KeyValidationInfoDTO removed for key : " + cacheKey);
    }
  }

  @SuppressWarnings("rawtypes")
  private static Cache getCustomKeyManagerCache() {
    long apimKeyCacheExpiry = 900L;
    if (!isCustomKeyCacheInitialized) {
      isCustomKeyCacheInitialized = true;
      
      CacheImpl cacheImpl = (CacheImpl)Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).createCacheBuilder("customKeyCache")
          .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS, apimKeyCacheExpiry))
          .setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS, apimKeyCacheExpiry)).setStoreByValue(false).build();
      
      cacheImpl.setCapacity(1000000);
      
      return cacheImpl;
      
    } else {
      return Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).getCache("customKeyCache");
    }

  }

}
