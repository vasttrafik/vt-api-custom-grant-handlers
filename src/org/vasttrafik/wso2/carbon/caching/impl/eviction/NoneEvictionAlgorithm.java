package org.vasttrafik.wso2.carbon.caching.impl.eviction;

import java.util.TreeSet;

import org.wso2.carbon.caching.impl.eviction.EvictionAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.caching.impl.CacheEntry;

public class NoneEvictionAlgorithm implements EvictionAlgorithm
{
  private static final Log log = LogFactory.getLog(NoneEvictionAlgorithm.class);
  
  public CacheEntry getEntryForEviction(TreeSet<CacheEntry> evictionList)
  {
    log.debug("Trying to find value to evict");
    return null;
  }
}