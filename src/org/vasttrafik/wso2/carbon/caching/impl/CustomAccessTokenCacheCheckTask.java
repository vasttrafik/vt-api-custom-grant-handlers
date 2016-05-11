package org.vasttrafik.wso2.carbon.caching.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.vasttrafik.wso2.carbon.identity.oauth2.dao.CustomTokenMgtDAO;
import org.wso2.carbon.caching.impl.CacheEntry;
import org.wso2.carbon.caching.impl.CacheImpl;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

public class CustomAccessTokenCacheCheckTask implements Runnable {
  private static final Log log = LogFactory.getLog(CustomAccessTokenCacheCheckTask.class);
  private CacheImpl<String, AccessTokenDO> cache;
  protected CustomTokenMgtDAO customTokenMgtDAO = new CustomTokenMgtDAO();

  public CustomAccessTokenCacheCheckTask(CacheImpl<String, AccessTokenDO> cache) {
    this.cache = cache;
  }

  public void addCacheForMonitoring(CacheImpl<String, AccessTokenDO> cache) {
    this.cache = cache;
  }

  public synchronized void run() {
    if (log.isDebugEnabled()) {
      log.debug("Cache check scheduler running...");
    }
    try {
      PrivilegedCarbonContext.startTenantFlow();
      PrivilegedCarbonContext cc = PrivilegedCarbonContext.getThreadLocalCarbonContext();
      cc.setTenantId(-1234);
      cc.setTenantDomain("carbon.super");

      Collection<CacheEntry<String, AccessTokenDO>> collection = cache.getAll();
      
      if(log.isDebugEnabled()) {
        log.debug("Attempting to persist " + collection.size() + " number of tokens from Custom Access Token Cache");
      }

      HashSet<String> set = new HashSet<String>();
      ArrayList<AccessTokenDO> list = new ArrayList<AccessTokenDO>();
      if (collection != null && collection.size() > 0) {

        for (CacheEntry<String, AccessTokenDO> cacheEntry : collection) {

          if (cacheEntry.getValue() != null) {
            list.add(cacheEntry.getValue());
            if (cacheEntry.getValue().getAccessToken() != null) {
              set.add(cacheEntry.getValue().getAccessToken());
            }
          }

        }

        // Send DOs to be written to database
        if (customTokenMgtDAO.storeAccessTokens(list) > 0) {
          
          try {
            
            cache.removeAll(set); // Remove written DOs from cache
            
          } catch (Exception e) {
            log.error("Problem removing batch of tokens from cache. Attempting to correct by removing one by one");
            // Remove one by one
            for(String key : set) {
              if(key != null)
                if(!cache.remove(key))
                  log.error("Problem removing key: " + key);
            }
          }
        }
      }

      if (log.isDebugEnabled()) {
        log.debug("Cache check completed for cache " + cache.getName());
      }

    } catch (IllegalStateException e) {
      log.debug("Error occurred while running CacheCheckTask", e);
    } catch (Throwable e) {
      log.error("Error occurred while running CacheCheckTask", e);
    } finally {
      PrivilegedCarbonContext.endTenantFlow();
    }
  }
}
