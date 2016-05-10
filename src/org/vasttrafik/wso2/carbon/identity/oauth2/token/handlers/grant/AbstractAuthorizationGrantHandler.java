package org.vasttrafik.wso2.carbon.identity.oauth2.token.handlers.grant;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang3.time.StopWatch;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.vasttrafik.org.wso2.carbon.apimgt.keymgt.util.CustomAPIKeyMgtUtil;
import org.vasttrafik.org.wso2.carbon.identity.oauth2.dao.CustomTokenMgtDAO;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.callback.OAuthCallbackManager;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public abstract class AbstractAuthorizationGrantHandler implements AuthorizationGrantHandler {
  private static Log log = LogFactory.getLog(AbstractAuthorizationGrantHandler.class);
  protected OAuthIssuer oauthIssuerImpl = OAuthServerConfiguration.getInstance().getOAuthTokenGenerator();
  protected TokenMgtDAO tokenMgtDAO;
  protected CustomTokenMgtDAO customTokenMgtDAO;
  protected OAuthCallbackManager callbackManager;
  protected boolean cacheEnabled;
  protected OAuthCache oauthCache;

  public void init() throws IdentityOAuth2Exception {
    this.tokenMgtDAO = new TokenMgtDAO();
    this.customTokenMgtDAO = new CustomTokenMgtDAO();
    this.callbackManager = new OAuthCallbackManager();
    if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
      this.cacheEnabled = true;
      this.oauthCache = OAuthCache.getInstance();
      
      log.info("oAuth cache initiated with capacity: " + this.oauthCache.getCapacity() + " and timeout: " + this.oauthCache.getCacheTimeout());
      
    }
  }

  public boolean isConfidentialClient() throws IdentityOAuth2Exception {
    return true;
  }

  public boolean issueRefreshToken() throws IdentityOAuth2Exception {
    return true;
  }

  public boolean isOfTypeApplicationUser() throws IdentityOAuth2Exception {
    return true;
  }

  public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
    
    StopWatch stopWatch = new StopWatch();
    StopWatch entireStopWatch = new StopWatch();
    StringBuilder builder = new StringBuilder();
    
    if(log.isInfoEnabled()) {
      entireStopWatch.start();
    }

    OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
    String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());

    String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
    String authorizedUser = tokReqMsgCtx.getAuthorizedUser().toString();
    boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
    String cacheKeyString;
    if (isUsernameCaseSensitive) {
      cacheKeyString = consumerKey + ":" + authorizedUser + ":" + scope;
    } else {
      cacheKeyString = consumerKey + ":" + authorizedUser.toLowerCase() + ":" + scope;
    }
    OAuthCacheKey cacheKey = new OAuthCacheKey(cacheKeyString);
    String userStoreDomain = null;
    if ((OAuth2Util.checkAccessTokenPartitioningEnabled()) && (OAuth2Util.checkUserNameAssertionEnabled())) {
      userStoreDomain = tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain();
    }
    String tokenType;
    if (isOfTypeApplicationUser()) {
      tokenType = "APPLICATION_USER";
    } else {
      tokenType = "APPLICATION";
    }
    
    if(log.isInfoEnabled()) {
      stopWatch.start();
    }
    
    synchronized ((consumerKey + ":" + authorizedUser + ":" + scope).intern()) {
      if (this.cacheEnabled) {
        AccessTokenDO existingAccessTokenDO = null;

        CacheEntry cacheEntry = (CacheEntry) this.oauthCache.getValueFromCache(cacheKey);
        if ((cacheEntry != null) && ((cacheEntry instanceof AccessTokenDO))) {
          existingAccessTokenDO = (AccessTokenDO) cacheEntry;
          if (log.isDebugEnabled()) {
            log.debug(
                "Retrieved active access token : " + existingAccessTokenDO.getAccessToken() + " for client Id " + consumerKey + ", user " + authorizedUser + " and scope " + scope + " from cache");
          }
          long expireTime = OAuth2Util.getTokenExpireTimeMillis(existingAccessTokenDO);
          if ((expireTime > 0L) || (expireTime < 0L)) {
            if (log.isDebugEnabled()) {
              if (expireTime > 0L) {
                log.debug("Access Token " + existingAccessTokenDO.getAccessToken() + " is still valid");
              } else {
                log.debug("Infinite lifetime Access Token " + existingAccessTokenDO.getAccessToken() + " found in cache");
              }
            }
            OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
            tokenRespDTO.setAccessToken(existingAccessTokenDO.getAccessToken());
            tokenRespDTO.setTokenId(existingAccessTokenDO.getTokenId());
            tokenRespDTO.setRefreshToken(null);

            if (expireTime > 0L) {
              tokenRespDTO.setExpiresIn(expireTime / 1000L);
              tokenRespDTO.setExpiresInMillis(expireTime);
            } else {
              tokenRespDTO.setExpiresIn(9223372036854775L);
              tokenRespDTO.setExpiresInMillis(Long.MAX_VALUE);
            }
            return tokenRespDTO;
          }
          this.oauthCache.clearCacheEntry(cacheKey);
          if (log.isDebugEnabled()) {
            log.debug("Access token " + existingAccessTokenDO.getAccessToken() + " is expired. Therefore cleared it from cache");
          }
        }
      }
      
      if(log.isInfoEnabled()) {
        stopWatch.stop();
        builder.append("Checking cache took: " + stopWatch.getTime() + " ms. ");
        stopWatch.reset();
        stopWatch.start();
      }

      AccessTokenDO existingAccessTokenDO = this.customTokenMgtDAO.retrieveLatestAccessToken(oAuth2AccessTokenReqDTO.getClientId(), tokReqMsgCtx.getAuthorizedUser(), userStoreDomain, scope, false);
      
      if(log.isInfoEnabled()) {
        stopWatch.stop();
        builder.append("Checking retrieve latest access token took: " + stopWatch.getTime() + " ms \r\n");
        stopWatch.reset();       
      }
      
      if (existingAccessTokenDO != null) {
        if (log.isDebugEnabled()) {
          log.debug(
              "Retrieved latest access token : " + existingAccessTokenDO.getAccessToken() + " for client Id " + consumerKey + ", user " + authorizedUser + " and scope " + scope + " from database");
        }
        long expireTime = OAuth2Util.getTokenExpireTimeMillis(existingAccessTokenDO);

        if (("ACTIVE".equals(existingAccessTokenDO.getTokenState())) && ((expireTime > 0L) || (expireTime < 0L))) {
          if (log.isDebugEnabled()) {
            if (expireTime > 0L) {
              log.debug("Access token " + existingAccessTokenDO.getAccessToken() + " is valid for another " + expireTime + "ms");
            } else {
              log.debug("Infinite lifetime Access Token " + existingAccessTokenDO.getAccessToken() + " found in cache");
            }
          }
          OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
          tokenRespDTO.setAccessToken(existingAccessTokenDO.getAccessToken());
          tokenRespDTO.setTokenId(existingAccessTokenDO.getTokenId());
          tokenRespDTO.setRefreshToken(null);

          if (expireTime > 0L) {
            tokenRespDTO.setExpiresIn(expireTime / 1000L);
            tokenRespDTO.setExpiresInMillis(expireTime);
          } else {
            tokenRespDTO.setExpiresIn(9223372036854775L);
            tokenRespDTO.setExpiresInMillis(Long.MAX_VALUE);
          }
          if (this.cacheEnabled) {
            this.oauthCache.addToCache(cacheKey, existingAccessTokenDO);
            /* Make it possible to lookup TokenDO from Token value */
            CustomAPIKeyMgtUtil.writeToKeyManagerCache(existingAccessTokenDO.getAccessToken(), this.convertAccesstokenDOToAPIKeyValidationInfoDTO(existingAccessTokenDO));
            
            //this.oauthCache.addToCache(new OAuthCacheKey(existingAccessTokenDO.getAccessToken()), existingAccessTokenDO);
            
            if (log.isDebugEnabled()) {
              log.debug("Access Token info was added to the cache for the cache key : " + cacheKey.getCacheKeyString() + " and " + existingAccessTokenDO.getAccessToken());
              log.debug("Is it possible to find value? " + this.oauthCache.getValueFromCache(new OAuthCacheKey(existingAccessTokenDO.getAccessToken())));
            }
          }
          return tokenRespDTO;
        }
        if (log.isDebugEnabled()) {
          log.debug("Access token + " + existingAccessTokenDO.getAccessToken() + " is not valid anymore");
        }
      } else if (log.isDebugEnabled()) {
        log.debug("No access token found in database for client Id " + consumerKey + ", user " + authorizedUser + " and scope " + scope + ". Therefore issuing new token");
      }
      if (log.isDebugEnabled()) {
        log.debug("Issuing a new access token for " + consumerKey + " AuthorizedUser : " + authorizedUser);
      }
      Timestamp timestamp = new Timestamp(new Date().getTime());

      long validityPeriodInMillis = OAuthServerConfiguration.getInstance().getApplicationAccessTokenValidityPeriodInSeconds() * 1000L;
      if (isOfTypeApplicationUser()) {
        validityPeriodInMillis = OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds() * 1000L;
      }
      long callbackValidityPeriod = tokReqMsgCtx.getValidityPeriod();
      if (callbackValidityPeriod != -1L) {
        validityPeriodInMillis = callbackValidityPeriod * 1000L;
      }

      if(log.isInfoEnabled()) {
        stopWatch.start();
      }
      
      String grantType = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();

      AccessTokenDO newAccessTokenDO =
          new AccessTokenDO(consumerKey, tokReqMsgCtx.getAuthorizedUser(), tokReqMsgCtx.getScope(), timestamp, timestamp, validityPeriodInMillis, validityPeriodInMillis, tokenType);
      String newAccessToken;
      try {
        String userName = tokReqMsgCtx.getAuthorizedUser().toString();

        tokReqMsgCtx.setValidityPeriod(validityPeriodInMillis);

        tokReqMsgCtx.setAccessTokenIssuedTime(timestamp.getTime());

        newAccessToken = this.oauthIssuerImpl.accessToken();
        if (OAuth2Util.checkUserNameAssertionEnabled()) {
          String accessTokenStrToEncode = newAccessToken + ":" + userName;
          newAccessToken = Base64Utils.encode(accessTokenStrToEncode.getBytes(Charsets.UTF_8));
        }
      } catch (OAuthSystemException e) {
        throw new IdentityOAuth2Exception("Error occurred while generating access token and refresh token", e);
      }
      newAccessTokenDO.setAccessToken(newAccessToken);
      newAccessTokenDO.setRefreshToken(null);
      newAccessTokenDO.setTokenState("ACTIVE");
      String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
      newAccessTokenDO.setTenantID(OAuth2Util.getTenantId(tenantDomain));
      newAccessTokenDO.setTokenId(UUID.randomUUID().toString());
      newAccessTokenDO.setGrantType(grantType);
      
      if(log.isInfoEnabled()) {
        stopWatch.stop();
        builder.append("Creating new access token DO took: " + stopWatch.getTime() + " ms. ");
        stopWatch.reset();
        stopWatch.start();       
      }
      
      storeAccessToken(oAuth2AccessTokenReqDTO, userStoreDomain, newAccessTokenDO, newAccessToken, existingAccessTokenDO);
      
      
      if(log.isInfoEnabled()) {
        stopWatch.stop();
        builder.append("Storing access token took: " + stopWatch.getTime() + " ms. ");
        stopWatch.reset();       
      }
      
      if (log.isDebugEnabled()) {
        log.debug("Persisted Access Token for Client ID : " + oAuth2AccessTokenReqDTO.getClientId() + ", Authorized User : " + tokReqMsgCtx.getAuthorizedUser() + ", Timestamp : " + timestamp
            + ", Validity period (s) : " + newAccessTokenDO.getValidityPeriod() + ", Scope : " + OAuth2Util.buildScopeString(tokReqMsgCtx.getScope()) + " and Token State : " + "ACTIVE");
      }
      if (this.cacheEnabled) {
        
        if(log.isInfoEnabled())
          stopWatch.start();
        
        this.oauthCache.addToCache(cacheKey, newAccessTokenDO);
        
        if(log.isInfoEnabled()) {
          stopWatch.stop();
          builder.append("Putting the access token DO object in oAuthCache took: " + stopWatch.getTime() + " ms. ");
          stopWatch.reset();
          stopWatch.start();
        }
        
        /* Make it possible to lookup TokenDO from Token value */
        CustomAPIKeyMgtUtil.writeToKeyManagerCache(newAccessTokenDO.getAccessToken(), this.convertAccesstokenDOToAPIKeyValidationInfoDTO(newAccessTokenDO));
        
        //this.oauthCache.addToCache(new OAuthCacheKey(newAccessTokenDO.getAccessToken()), newAccessTokenDO);
        
        if(log.isInfoEnabled()) {
          stopWatch.stop();
          builder.append("Putting the APIKeyValidationInfoDTO object in key cache took: " + stopWatch.getTime() + " ms. Size: " );
        }

        if (log.isDebugEnabled()) {
          log.debug("Access token was added to OAuthCache for cache key : " + cacheKey.getCacheKeyString() + " and " + newAccessTokenDO.getAccessToken());
        }
      }
      OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
      tokenRespDTO.setAccessToken(newAccessToken);
      tokenRespDTO.setTokenId(newAccessTokenDO.getTokenId());
      tokenRespDTO.setRefreshToken(null);

      if (validityPeriodInMillis > 0L) {
        tokenRespDTO.setExpiresInMillis(newAccessTokenDO.getValidityPeriodInMillis());
        tokenRespDTO.setExpiresIn(newAccessTokenDO.getValidityPeriod());
      } else {
        tokenRespDTO.setExpiresInMillis(Long.MAX_VALUE);
        tokenRespDTO.setExpiresIn(Long.MAX_VALUE);
      }
      tokenRespDTO.setAuthorizedScopes(scope);
      
      if(log.isInfoEnabled()) {
        entireStopWatch.stop();
        builder.append("Entire invocation took: " + entireStopWatch.getTime() + " ms. for scope: " + scope);
        log.info(builder.toString());
      }
      
      return tokenRespDTO;
    }
  }

  protected void storeAccessToken(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String userStoreDomain, AccessTokenDO newAccessTokenDO, String newAccessToken, AccessTokenDO existingAccessTokenDO)
      throws IdentityOAuth2Exception {
    try {
      this.tokenMgtDAO.storeAccessToken(newAccessToken, oAuth2AccessTokenReqDTO.getClientId(), newAccessTokenDO, existingAccessTokenDO, userStoreDomain);
    } catch (IdentityException e) {
      throw new IdentityOAuth2Exception("Error occurred while storing new access token : " + newAccessToken, e);
    }
  }
  
  protected void persistAccessToken(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String userStoreDomain, AccessTokenDO newAccessTokenDO, String newAccessToken, AccessTokenDO existingAccessTokenDO)
      throws IdentityOAuth2Exception {
    try {
      this.tokenMgtDAO.persistAccessToken(newAccessToken, oAuth2AccessTokenReqDTO.getClientId(), newAccessTokenDO, existingAccessTokenDO, userStoreDomain);
    } catch (IdentityException e) {
      throw new IdentityOAuth2Exception("Error occurred while storing new access token : " + newAccessToken, e);
    }
  }

  public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
    OAuthCallback authzCallback = new OAuthCallback(tokReqMsgCtx.getAuthorizedUser(), tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_TOKEN);

    authzCallback.setRequestedScope(tokReqMsgCtx.getScope());
    if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString())) {
      authzCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf("SAML20_BEARER".toString()));
    } else if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString())) {
      authzCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf("IWA_NTLM".toString()));
    } else {
      authzCallback.setGrantType(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType());
    }
    this.callbackManager.handleCallback(authzCallback);
    tokReqMsgCtx.setValidityPeriod(authzCallback.getValidityPeriod());
    return authzCallback.isAuthorized();
  }

  public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
    OAuthCallback scopeValidationCallback =
        new OAuthCallback(tokReqMsgCtx.getAuthorizedUser(), tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_TOKEN);

    scopeValidationCallback.setRequestedScope(tokReqMsgCtx.getScope());
    if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString())) {
      scopeValidationCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf("SAML20_BEARER".toString()));
    } else if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString())) {
      scopeValidationCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf("IWA_NTLM".toString()));
    } else {
      scopeValidationCallback.setGrantType(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType());
    }
    this.callbackManager.handleCallback(scopeValidationCallback);
    tokReqMsgCtx.setValidityPeriod(scopeValidationCallback.getValidityPeriod());
    tokReqMsgCtx.setScope(scopeValidationCallback.getApprovedScope());
    return scopeValidationCallback.isValidScope();
  }

  public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
    OAuth2AccessTokenReqDTO tokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
    String grantType = tokenReqDTO.getGrantType();

    AppInfoCache appInfoCache = AppInfoCache.getInstance();
    OAuthAppDO oAuthAppDO = (OAuthAppDO) appInfoCache.getValueFromCache(tokenReqDTO.getClientId());
    if (oAuthAppDO == null) {
      try {
        oAuthAppDO = new OAuthAppDAO().getAppInformation(tokenReqDTO.getClientId());
        appInfoCache.addToCache(tokenReqDTO.getClientId(), oAuthAppDO);
      } catch (InvalidOAuthClientException e) {
        throw new IdentityOAuth2Exception(e.getMessage(), e);
      }
    }
    if ((oAuthAppDO.getGrantTypes() != null) && (!oAuthAppDO.getGrantTypes().contains(grantType))) {
      if (log.isDebugEnabled()) {
        log.debug("Unsupported Grant Type : " + grantType + " for client id : " + tokenReqDTO.getClientId());
      }
      return false;
    }
    return true;
  }
  
  private APIKeyValidationInfoDTO convertAccesstokenDOToAPIKeyValidationInfoDTO(AccessTokenDO accessTokenDO) {

    APIKeyValidationInfoDTO apiKeyValidationInfoDTO = new APIKeyValidationInfoDTO();

    apiKeyValidationInfoDTO.setAuthorized(true);
    apiKeyValidationInfoDTO.setEndUserName(accessTokenDO.getAuthzUser().getUserName());
    apiKeyValidationInfoDTO.setConsumerKey(accessTokenDO.getConsumerKey());
    apiKeyValidationInfoDTO.setIssuedTime((accessTokenDO != null ? accessTokenDO.getIssuedTime().getTime() : System.currentTimeMillis()));
    apiKeyValidationInfoDTO.setValidityPeriod(accessTokenDO.getValidityPeriod() * 1000L);
    if (accessTokenDO.getScope() != null) {
      Set<String> scopeSet = new HashSet<String>(Arrays.asList(accessTokenDO.getScope()));
      apiKeyValidationInfoDTO.setScopes(scopeSet);
    }
    
    return apiKeyValidationInfoDTO;
    
  }
}
