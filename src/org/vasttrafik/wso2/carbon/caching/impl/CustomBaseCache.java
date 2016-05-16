package org.vasttrafik.wso2.carbon.caching.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.vasttrafik.wso2.carbon.caching.impl.eviction.NoneEvictionAlgorithm;

import org.wso2.carbon.caching.impl.CacheImpl;
import org.wso2.carbon.caching.impl.eviction.EvictionAlgorithm;
import org.wso2.carbon.identity.application.common.listener.AbstractCacheListener;
import org.wso2.carbon.identity.core.model.IdentityCacheConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.cache.Cache;
import javax.cache.CacheBuilder;
import javax.cache.CacheConfiguration;
import javax.cache.CacheManager;
import javax.cache.Caching;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * A base class for all cache implementations in Identity Application Management modules.
 */
public class CustomBaseCache<K extends Serializable, V extends Serializable> {

	private static Log log = LogFactory.getLog(CustomBaseCache.class);

	private static final String CACHE_MANAGER_NAME = "CustomApplicationManagementCacheManager";
	private static final String LOCAL_CACHE_PREFIX = "$__local__$.";
  
	private CacheBuilder<K, V> cacheBuilder;
	private String cacheName;
	private int capacity = -1;
	private int timeout = -1;
	private EvictionAlgorithm evictionAlgorithm;
	private List<AbstractCacheListener> cacheListeners = new ArrayList<AbstractCacheListener>();

	public CustomBaseCache(String cacheName, int timeout, int capacity, EvictionAlgorithm evictionAlgorithm) {
		this.cacheName = cacheName;
		this.timeout = timeout;
		this.capacity = capacity;
		this.evictionAlgorithm = evictionAlgorithm;
	}

	public Cache<K, V> getBaseCache() {

		Cache<K, V> cache = null;

		// Get the cache manager
		CacheManager cacheManager = Caching.getCacheManagerFactory().getCacheManager(CACHE_MANAGER_NAME);
		

		if (getCacheTimeout() > 0 && cacheBuilder == null) {
			synchronized (cacheName.intern()) {
				if (cacheBuilder == null) {
					// Get the cache cache configuration
					getCacheConfiguration();
					
					cacheManager.removeCache(cacheName);
					cacheBuilder = cacheManager.<K, V>createCacheBuilder(cacheName)
							.setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS, getCacheTimeout()))
							.setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS, getCacheTimeout()))
							.setStoreByValue(false);
					cache = cacheBuilder.build();
					
					setCapacity((CacheImpl)cache);
					setEvictionAlgorithm((CacheImpl)cache);

					for (AbstractCacheListener cacheListener : cacheListeners) {
						if (cacheListener.isEnable()) {
							this.cacheBuilder.registerCacheEntryListener(cacheListener);
						}
					}
					
					log.info("Cache " + cacheName + " initialized with capacity: " + capacity + 
							" ,timeout " + timeout + " and eviction algorithm " + evictionAlgorithm);
				} 
				else {
					cache = cacheManager.getCache(cacheName);
				}
			}
		} 
		else {
			cache = cacheManager.getCache(cacheName);
		}

		return cache;
	}

  /**
   * Add a cache entry.
   *
   * @param key Key which cache entry is indexed.
   * @param entry Actual object where cache entry is placed.
   */
	public void addToCache(K key, V entry) {
		long l = System.currentTimeMillis();
		Cache<K, V> cache = getBaseCache();
    
		if (cache != null) {
			cache.put(key, entry);
		}
		logIfSlow("addToCache",l);
	}

  /**
   * Retrieves a cache entry.
   *
   * @param key CacheKey
   * @return Cached entry.
   */
	public V getValueFromCache(K key) {
		if (key == null) {
			return null;
		}
	
		long l = System.currentTimeMillis();
		Cache<K, V> cache = getBaseCache();
    
		if (cache != null && cache.get(key) != null) {
			return (V) cache.get(key);
		}
		logIfSlow("getValueFromCache",l);
		return null;
	}

  /**
   * Clears a cache entry.
   *
   * @param key Key to clear cache.
   */
	public void clearCacheEntry(K key) {
		long l = System.currentTimeMillis();
		Cache<K, V> cache = getBaseCache();
		if (cache != null) {
			cache.remove(key);
		}
		logIfSlow("clearCacheEntry",l);
	}

  /**
   * Remove everything in the cache.
   */
	public void clear() {
		long l = System.currentTimeMillis();
		Cache<K, V> cache = getBaseCache();
    
		if (cache != null) {
			cache.removeAll();
		}
		logIfSlow("clear",l);
	}

	public void addListener(AbstractCacheListener listener) {
		cacheListeners.add(listener);
	}

	public int getCacheTimeout() {
		return this.timeout;
	}

	public int getCapacity() {
		return this.capacity;
	}

	private void setCapacity(CacheImpl cache) {
		if (getCapacity() > 0) {
			cache.setCapacity(getCapacity());
		}
	}
  
	private void setEvictionAlgorithm(CacheImpl cache) {
		if (evictionAlgorithm != null) {
			cache.setEvictionAlgorithm(evictionAlgorithm);
	    
			if (evictionAlgorithm instanceof NoneEvictionAlgorithm)
				((NoneEvictionAlgorithm)evictionAlgorithm).setCache(cache);
		}
	}
	
    private void getCacheConfiguration() {
    	IdentityCacheConfig identityCacheConfig = 
        		IdentityUtil.getIdentityCacheConfig(CACHE_MANAGER_NAME, cacheName);
    	
    	if (identityCacheConfig == null) {
    		if (cacheName.startsWith(LOCAL_CACHE_PREFIX)) {
    			String localCacheName = cacheName.substring(LOCAL_CACHE_PREFIX.length());
    			// Try to match with distributed cache name instead
    			identityCacheConfig = 
    	        		IdentityUtil.getIdentityCacheConfig(CACHE_MANAGER_NAME, localCacheName);
    			
    			if (identityCacheConfig != null)
    				cacheName = localCacheName;
    		}
    		else {
    			// Try matching with local name instead
    			identityCacheConfig = 
    	        		IdentityUtil.getIdentityCacheConfig(CACHE_MANAGER_NAME, LOCAL_CACHE_PREFIX + cacheName);
    			
    			if (identityCacheConfig != null)
    				cacheName = LOCAL_CACHE_PREFIX + cacheName;
    		}
    	}
    	
    	if (identityCacheConfig != null) {
    		timeout  = identityCacheConfig.getTimeout();
    		capacity = identityCacheConfig.getCapacity();
    	}
    }
  
	private void logIfSlow(String method, long l) {
		long elapsed = System.currentTimeMillis() - l;
		if (elapsed > 150)
			log.info("CustomBaseCache." + method + ", cache name " + cacheName + " took:" + elapsed + " ms");
	}
}
