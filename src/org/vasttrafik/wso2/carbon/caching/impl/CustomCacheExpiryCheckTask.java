package org.vasttrafik.wso2.carbon.caching.impl;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.caching.impl.CacheImpl;
import org.wso2.carbon.context.PrivilegedCarbonContext;

public class CustomCacheExpiryCheckTask implements Runnable {
  private static final Log log = LogFactory.getLog(CustomCacheExpiryCheckTask.class);

  private CacheImpl<?, ?> cache;

  public CustomCacheExpiryCheckTask(CacheImpl<?, ?> cache) {
    this.cache = cache;
  }

  public void addCacheForMonitoring(CacheImpl<String, APIKeyValidationInfoDTO> cache) {
    this.cache = cache;
  }

  public synchronized void run() {
    try {
      PrivilegedCarbonContext.startTenantFlow();
      PrivilegedCarbonContext cc = PrivilegedCarbonContext.getThreadLocalCarbonContext();
      cc.setTenantId(-1234);
      cc.setTenantDomain("carbon.super");

      Collection<?> collection = cache.getAll();

      if (log.isDebugEnabled()) {
        log.debug("There's currently " + collection.size() + " number of items in cache " + this.cache.getName());
      }

    } catch (Throwable e) {
      log.error("Error occurred while running CacheExpiryCheckTask", e);
    } finally {
      PrivilegedCarbonContext.endTenantFlow();
    }
  }
}
