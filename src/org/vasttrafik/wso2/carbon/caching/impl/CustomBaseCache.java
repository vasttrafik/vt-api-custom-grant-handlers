package org.vasttrafik.wso2.carbon.caching.impl;

import org.wso2.carbon.caching.impl.CacheImpl;
import org.wso2.carbon.identity.application.common.listener.AbstractCacheListener;

import javax.cache.Cache;
import javax.cache.CacheBuilder;
import javax.cache.CacheConfiguration;
import javax.cache.CacheManager;
import javax.cache.Caching;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * A base class for all cache implementations in Identity Application Management modules.
 */
public class CustomBaseCache<K extends Serializable, V extends Serializable> {

  private static final String CACHE_MANAGER_NAME = "CacheManager";
  private CacheBuilder<K, V> cacheBuilder;
  private String cacheName;
  private int capacity = -1;
  private int timeout = -1;
  private List<AbstractCacheListener> cacheListeners = new ArrayList<AbstractCacheListener>();

  public CustomBaseCache(String cacheName, int timeout, int capacity) {
    this.cacheName = cacheName;
    this.timeout = timeout;
    this.capacity = capacity;
  }

  public Cache<K, V> getBaseCache() {

    Cache<K, V> cache = null;

    CacheManager cacheManager = Caching.getCacheManagerFactory().getCacheManager(CACHE_MANAGER_NAME);

    if (getCacheTimeout() > 0 && cacheBuilder == null) {
      synchronized (cacheName.intern()) {
        if (cacheBuilder == null) {
          cacheManager.removeCache(cacheName);
          cacheBuilder = cacheManager.<K, V>createCacheBuilder(cacheName).setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS, getCacheTimeout()))
              .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS, getCacheTimeout())).setStoreByValue(false);
          cache = cacheBuilder.build();

          for (AbstractCacheListener cacheListener : cacheListeners) {
            if (cacheListener.isEnable()) {
              this.cacheBuilder.registerCacheEntryListener(cacheListener);
            }
          }

          setCapacity((CacheImpl) cache);
        } else {
          cache = cacheManager.getCache(cacheName);
          setCapacity((CacheImpl) cache);
        }
      }

    } else {
      cache = cacheManager.getCache(cacheName);
      setCapacity((CacheImpl) cache);

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

    Cache<K, V> cache = getBaseCache();
    if (cache != null) {
      cache.put(key, entry);
    }
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
    Cache<K, V> cache = getBaseCache();
    if (cache != null && cache.get(key) != null) {
      return (V) cache.get(key);
    }
    return null;

  }

  /**
   * Clears a cache entry.
   *
   * @param key Key to clear cache.
   */
  public void clearCacheEntry(K key) {

    Cache<K, V> cache = getBaseCache();
    if (cache != null) {
      cache.remove(key);
    }
  }

  /**
   * Remove everything in the cache.
   */
  public void clear() {

    Cache<K, V> cache = getBaseCache();
    if (cache != null) {
      cache.removeAll();
    }
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
}
