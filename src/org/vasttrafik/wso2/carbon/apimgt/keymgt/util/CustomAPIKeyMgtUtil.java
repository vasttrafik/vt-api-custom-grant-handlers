package org.vasttrafik.wso2.carbon.apimgt.keymgt.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.vasttrafik.wso2.carbon.caching.impl.eviction.NoneEvictionAlgorithm;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.caching.impl.CacheImpl;
import org.wso2.carbon.caching.impl.CacheEntry;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class CustomAPIKeyMgtUtil {

  private static final Log log = LogFactory.getLog(CustomAPIKeyMgtUtil.class);

  /**
   * Get the KeyValidationInfo object from cache, for a given cache-Key
   *
   * @param cacheKey Key for the Cache Entry
   * @return APIKeyValidationInfoDTO
   * @throws APIKeyMgtException
   */
  public static APIKeyValidationInfoDTO getFromCustomKeyManagerCache(String cacheKey) {

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
  public static void writeToCustomKeyManagerCache(String cacheKey, APIKeyValidationInfoDTO validationInfoDTO) {

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
      Cache<String, CacheEntry<String, AccessTokenDO>> cache = getCustomAccessTokenCache();
      cache.put(authKey, new CacheEntry<String, AccessTokenDO>(authKey, accessTokenDO));
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
  
  /**
   * Remove all AccessTokenDO from Access Token Cache
   *
   * @param set the set objects to remove from the cache
   */
  public static void removeAllFromCustomAccessTokenCache(Set<String> set) {

    if (set != null && set.size() > 0) {
      Cache<String, CacheEntry<String, AccessTokenDO>> cache = getCustomAccessTokenCache();
      cache.removeAll(set);
      log.debug("Removed all entries from access token cache found in the set");
    }
  }
  
  /**
   * Retrieve all entries in Access Token Cache
   *
   */
  public static Collection<CacheEntry<String, CacheEntry<String, AccessTokenDO>>> getAllFromCustomAccessTokenCacheCache() {

    CacheImpl<String, CacheEntry<String, AccessTokenDO>> cacheImpl = getCustomAccessTokenCache();
    return cacheImpl.getAll();
  }

  @SuppressWarnings("unchecked")
  private static Cache<String, APIKeyValidationInfoDTO> getCustomKeyManagerCache() {

    Cache<String, APIKeyValidationInfoDTO> cache;

    if ((cache = Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).getCache("customKeyCache")) != null)
      return cache;

    long apimCustomKeyCacheExpiry = 3600L; // 1 hour
    long apimCustomKeyCacheCapacity = 1000000L;
 
    @SuppressWarnings("rawtypes")
    CacheImpl<String, APIKeyValidationInfoDTO> cacheImpl = (CacheImpl) Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).createCacheBuilder("customKeyCache")
        .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS, apimCustomKeyCacheExpiry))
        .setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS, apimCustomKeyCacheExpiry)).setStoreByValue(false).build();

    cacheImpl.setCapacity(apimCustomKeyCacheCapacity);
    cacheImpl.setEvictionAlgorithm(new NoneEvictionAlgorithm());

    return cacheImpl;

  }
  
  @SuppressWarnings("unchecked")
  private static CacheImpl<String, CacheEntry<String, AccessTokenDO>> getCustomAccessTokenCache() {

    Cache<String, CacheEntry<String, AccessTokenDO>> cache;

    if ((cache = Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).getCache("customAccessTokenCache")) != null)
      return (CacheImpl<String, CacheEntry<String, AccessTokenDO>>)cache;

    long apimKeyCacheExpiry = 18000L; // 5 hours
    long apimKeyCacheCapacity = 100000L;

    @SuppressWarnings("rawtypes")
    CacheImpl<String, CacheEntry<String, AccessTokenDO>> cacheImpl = (CacheImpl) Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).createCacheBuilder("customKeyCache")
        .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS, apimKeyCacheExpiry))
        .setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS, apimKeyCacheExpiry)).setStoreByValue(false).build();

    cacheImpl.setCapacity(apimKeyCacheCapacity);
    cacheImpl.setEvictionAlgorithm(new NoneEvictionAlgorithm());

    return cacheImpl;

  }

}
