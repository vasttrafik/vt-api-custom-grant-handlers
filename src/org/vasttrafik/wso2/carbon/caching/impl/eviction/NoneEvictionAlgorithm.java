package org.vasttrafik.wso2.carbon.caching.impl.eviction;

import java.util.TreeSet;

import org.wso2.carbon.caching.impl.eviction.EvictionAlgorithm;
import org.wso2.carbon.caching.impl.CacheEntry;
import org.wso2.carbon.caching.impl.CacheImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class NoneEvictionAlgorithm implements EvictionAlgorithm
{
  private static final Log log = LogFactory.getLog(NoneEvictionAlgorithm.class);
  @SuppressWarnings("rawtypes")
  private CacheImpl cache;
  
  public NoneEvictionAlgorithm() {
  }
  
  @SuppressWarnings("rawtypes")
  public void setCache(CacheImpl cache) {
	  this.cache = cache;
  }
  
  // TO-DO: Check if number of entries exceed capacity, if so, try to find something to evict instead of going to sleep...
  @SuppressWarnings({"rawtypes", "static-access"})
  public CacheEntry getEntryForEviction(TreeSet<CacheEntry> evictionList)
  {
	if (cache != null) {
	  final String message = "Cache " + cache.getName() + " with " + cache.getAll().size() + " entries going to sleep...";
      log.info(message);
	}
    
    try {

    	Thread.currentThread().sleep(60000L);
    }
    catch (InterruptedException i) {
      log.info("Interrupted");	
    }
    catch (Exception e) {}
    return null;
  }
}