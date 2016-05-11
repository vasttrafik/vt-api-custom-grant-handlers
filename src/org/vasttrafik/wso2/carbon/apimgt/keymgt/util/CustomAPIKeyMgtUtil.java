package org.vasttrafik.wso2.carbon.apimgt.keymgt.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.vasttrafik.wso2.carbon.caching.impl.CustomAccessTokenCacheCheckTask;
import org.vasttrafik.wso2.carbon.caching.impl.CustomAccessTokenCache;
import org.vasttrafik.wso2.carbon.caching.impl.CustomKeyCache;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.caching.impl.CacheImpl;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;


import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

public class CustomAPIKeyMgtUtil {

  private static final Log log = LogFactory.getLog(CustomAPIKeyMgtUtil.class);

  private static CustomKeyCache customKeyCache = CustomKeyCache.getInstance();
  private static CustomAccessTokenCache customAccessTokenCache = CustomAccessTokenCache.getInstance();

  static {
    ThreadFactory threadFactory = new ThreadFactory() {
      public Thread newThread(Runnable runnable) {
        Thread th = new Thread(runnable);
        return th;
      }
    };

    Executors.newSingleThreadScheduledExecutor(threadFactory).scheduleAtFixedRate(new CustomAccessTokenCacheCheckTask((CacheImpl<String, AccessTokenDO>) customAccessTokenCache.getBaseCache()), 10L, 10L, TimeUnit.SECONDS);
  }

  /**
   * Get the KeyValidationInfo object from cache, for a given cache-Key
   *
   * @param cacheKey Key for the Cache Entry
   * @return APIKeyValidationInfoDTO
   * @throws APIKeyMgtException
   */
  public static APIKeyValidationInfoDTO getFromCustomKeyManagerCache(String cacheKey) {

    APIKeyValidationInfoDTO info = customKeyCache.getValueFromCache(cacheKey);

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
  public static void writeToCustomKeyManagerCache(String cacheKey, APIKeyValidationInfoDTO validationInfoDTO) {

    if (cacheKey != null) {
      if (log.isDebugEnabled()) {
        log.debug("Storing KeyValidationDTO for key: " + cacheKey + ".");
      }
    }

    if (validationInfoDTO != null) {
      customKeyCache.addToCache(cacheKey, validationInfoDTO);
    }
  }

  /**
   * Store AccessTokenDO in Access Token Cache
   *
   * @param authKey Auth key for the Cache Entry to be stored
   * @param accessTokenDO AccessTokenDO object
   */
  public static void writeToCustomAccessTokenCache(String authKey, AccessTokenDO accessTokenDO) {

    if (authKey != null) {
      if (log.isDebugEnabled()) {
        log.debug("Storing AccessTokenDO for key: " + authKey + ".");
      }
    }

    if (accessTokenDO != null) {
      customAccessTokenCache.addToCache(authKey, accessTokenDO);
    }
  }

  /**
   * Remove APIKeyValidationInfoDTO from Key Manager Cache
   *
   * @param cacheKey Key for the Cache Entry to be removed
   */
  public static void removeFromCustomKeyManagerCache(String cacheKey) {

    if (cacheKey != null) {
      customKeyCache.clearCacheEntry(cacheKey);
      log.debug("KeyValidationInfoDTO removed for key : " + cacheKey);
    }
  }

}
