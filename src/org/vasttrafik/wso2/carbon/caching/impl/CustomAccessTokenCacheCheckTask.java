package org.vasttrafik.wso2.carbon.caching.impl;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.vasttrafik.wso2.carbon.identity.oauth2.dao.CustomTokenMgtDAO;
import org.wso2.carbon.caching.impl.CacheEntry;
import org.wso2.carbon.caching.impl.CacheImpl;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public class CustomAccessTokenCacheCheckTask implements Runnable {
  private static final Log log = LogFactory.getLog(CustomAccessTokenCacheCheckTask.class);

  private static int numberOfFailedAttempts = 0;

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

      if (log.isDebugEnabled()) {
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

        try {
          // Send DOs to be written to database
          if (customTokenMgtDAO.storeAccessTokens(list) > 0) {

            removeFromCache(set);
            
          }
        } catch (Exception e) {
          
          numberOfFailedAttempts++;
          
          log.error("Problem writing tokens to Database. Number of failed attempts: " + numberOfFailedAttempts, e);

          if (numberOfFailedAttempts > 2) {
            
            log.error("Failed to write tokens to database more than 2 times, initiating exception handling. Writing tokens to file");

            SimpleDateFormat sdfDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
            sdfDate.setTimeZone(TimeZone.getTimeZone("UTC"));
            SimpleDateFormat sdfFile = new SimpleDateFormat("yyyyMMddHHmmssSSS");
            Date now = new Date();

            String filePath = System.getProperty("carbon.home") + File.separator + sdfFile.format(now) + "-TOKEN-ERROR.sql";

            PrintWriter out = null;
            String oauthSql = "";
            AccessTokenDO tokenDO = null;
            AuthenticatedUser user = null;
            try {
              out = new PrintWriter(new OutputStreamWriter(new BufferedOutputStream(new FileOutputStream(filePath)), "UTF-8"), false);
              for (int i = 0; i < list.size(); i++) {

                tokenDO = list.get(i);

                // Get the authenticated user
                user = tokenDO.getAuthzUser();
                // Get the tenant id and token id
                int tenantId = OAuth2Util.getTenantId(user.getTenantDomain());
                String accessTokenId = tokenDO.getTokenId();

                oauthSql = "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN (ACCESS_TOKEN, REFRESH_TOKEN, CONSUMER_KEY_ID, AUTHZ_USER, TENANT_ID, USER_DOMAIN, "
                    + "TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_SCOPE_HASH, TOKEN_STATE, "
                    + "USER_TYPE, TOKEN_ID, GRANT_TYPE, SUBJECT_IDENTIFIER) " + "SELECT '" + tokenDO.getAccessToken() + "', " + tokenDO.getRefreshToken() + ", ID, '" + user.getUserName() + "', '" + tenantId
                    + "', '" + user.getUserStoreDomain() + "', '" + sdfDate.format(tokenDO.getIssuedTime()) + "', '" + sdfDate.format(tokenDO.getRefreshTokenIssuedTime()) + "', "
                    + tokenDO.getValidityPeriodInMillis() + "," + tokenDO.getRefreshTokenValidityPeriodInMillis() + ", '" + OAuth2Util.hashScopes(tokenDO.getScope()) + "', '" + tokenDO.getTokenState()
                    + "', '" + tokenDO.getTokenType() + "', '" + accessTokenId + "', '" + tokenDO.getGrantType() + "', " + user.getAuthenticatedSubjectIdentifier()
                    + " FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY='" + tokenDO.getConsumerKey() + "';";

                out.println(oauthSql);
              }
            } catch (Exception ex) {
              log.error("Problem writing tokens to file: " + filePath, ex);
            } finally {
              if (out != null) {
                out.flush();
                out.close();
              }
            }
            
            removeFromCache(set);
            
            log.error("Flushed token cache to disk in file: " + filePath);

          }
          
          customTokenMgtDAO = new CustomTokenMgtDAO();
          
        }

      }

      if (log.isDebugEnabled()) {
        log.debug("Cache check completed for cache " + cache.getName());
      }

    } catch (Throwable e) {
      log.error("Error occurred while running CacheCheckTask", e);
    } finally {
      PrivilegedCarbonContext.endTenantFlow();
    }
  }
  
  private void removeFromCache(HashSet<String> set) {
    
    try {

      cache.removeAll(set); // Remove written DOs from cache

    } catch (Exception e) {
      log.error("Problem removing batch of tokens from cache. Attempting to correct by removing one by one");
      // Remove one by one
      for (String key : set) {
        if (key != null)
          if (!cache.remove(key))
            log.error("Problem removing key: " + key);
      }
    }
    
    numberOfFailedAttempts = 0;
  }
}
