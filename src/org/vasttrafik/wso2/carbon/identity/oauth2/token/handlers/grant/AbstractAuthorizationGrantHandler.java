package org.vasttrafik.wso2.carbon.identity.oauth2.token.handlers.grant;

import java.sql.Timestamp;
import java.util.Date;
import org.apache.amber.oauth2.as.issuer.MD5Generator;
import org.apache.amber.oauth2.as.issuer.OAuthIssuer;
import org.apache.amber.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.cache.CacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.callback.OAuthCallbackManager;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;

public abstract class AbstractAuthorizationGrantHandler implements AuthorizationGrantHandler {
	  private static Log log = LogFactory.getLog(AbstractAuthorizationGrantHandler.class);
	  protected TokenMgtDAO tokenMgtDAO;
	  protected final OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());
	  protected OAuthCallbackManager callbackManager;
	  protected boolean cacheEnabled;
	  protected OAuthCache oauthCache;
	  
	  public void init()
	    throws IdentityOAuth2Exception
	  {
	    this.tokenMgtDAO = new TokenMgtDAO();
	    this.callbackManager = new OAuthCallbackManager();
	    if (OAuthServerConfiguration.getInstance().isCacheEnabled())
	    {
	      this.cacheEnabled = true;
	      this.oauthCache = OAuthCache.getInstance();
	    }
	  }
	  
	  public boolean isConfidentialClient()
	    throws IdentityOAuth2Exception
	  {
	    return true;
	  }
	  
	  public boolean issueRefreshToken()
	    throws IdentityOAuth2Exception
	  {
	    return true;
	  }
	  
	  public boolean isOfTypeApplicationUser()
	    throws IdentityOAuth2Exception
	  {
	    return true;
	  }
	  
	  public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
	    throws IdentityOAuth2Exception
	  {
	    OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
	    String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
	    
	    String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
	    String authorizedUser = tokReqMsgCtx.getAuthorizedUser();
	    CacheKey cacheKey = new OAuthCacheKey(consumerKey + ":" + authorizedUser.toLowerCase() + ":" + scope);
	    String userStoreDomain = null;
	    if ((OAuth2Util.checkAccessTokenPartitioningEnabled()) && (OAuth2Util.checkUserNameAssertionEnabled())) {
	      userStoreDomain = OAuth2Util.getUserStoreDomainFromUserId(tokReqMsgCtx.getAuthorizedUser());
	    }
	    String tokenType;
	    if (isOfTypeApplicationUser()) {
	      tokenType = "APPLICATION_USER";
	    } else {
	      tokenType = "APPLICATION";
	    }
	    synchronized ((consumerKey + ":" + authorizedUser + ":" + scope).intern())
	    {
	      try
	      {
	        if (this.cacheEnabled)
	        {
	        	
	        	if(log.isDebugEnabled()) {
	        		log.debug("Attempting to retrieve key from cache");
	        	}    		
	        	
	          AccessTokenDO AccessTokenDO = (AccessTokenDO)this.oauthCache.getValueFromCache(cacheKey);
	          
	          if(log.isDebugEnabled()) {
	        		log.debug("Completed cache lookup");
	        	} 
	          
	          if (AccessTokenDO != null)
	          {
	            long expireTime = OAuth2Util.getTokenExpireTimeMillis(AccessTokenDO);
	            if (expireTime > 0L)
	            {
	              OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
	              tokenRespDTO.setAccessToken(AccessTokenDO.getAccessToken());
	              tokenRespDTO.setExpiresIn(expireTime / 1000L);
	              tokenRespDTO.setExpiresInMillis(expireTime);
	              if (log.isDebugEnabled()) {
	                log.debug("Access Token info retrieved from the cache and served to client with client id : " + oAuth2AccessTokenReqDTO.getClientId());
	              }
	              return tokenRespDTO;
	            }
	            this.oauthCache.clearCacheEntry(cacheKey);
	          }
	        }
        	if(log.isDebugEnabled()) {
        		log.debug("Attempting to retrieve valid access token from database");
        	}  
	        AccessTokenDO accessTokenDO = this.tokenMgtDAO.getValidAccessTokenIfExist(oAuth2AccessTokenReqDTO.getClientId(), tokReqMsgCtx.getAuthorizedUser(), userStoreDomain, scope);
	        
        	if(log.isDebugEnabled()) {
        		log.debug("Returned from database call");	
        	}  
	        
	        if (accessTokenDO != null)
	        {
	          accessTokenDO.setScope(tokReqMsgCtx.getScope());
	          accessTokenDO.setTokenType(tokenType);
	          OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
	          tokenRespDTO.setAccessToken(accessTokenDO.getAccessToken());
	          tokenRespDTO.setRefreshToken(null);
	          long expireTime = OAuth2Util.getTokenExpireTimeMillis(accessTokenDO);
	          tokenRespDTO.setExpiresIn(expireTime / 1000L);
	          tokenRespDTO.setExpiresInMillis(expireTime);
	          if (this.cacheEnabled)
	          {
	            if (log.isDebugEnabled()) {
	              log.debug("Access Token info was added to the cache for the client id : " + oAuth2AccessTokenReqDTO.getClientId());
	            }
	            this.oauthCache.addToCache(cacheKey, accessTokenDO);
	          }
	          
	          tokenRespDTO.setRefreshToken(null);

	          if (log.isDebugEnabled()) {
		            log.debug("Retrieved existing valid access token for client id : " + oAuth2AccessTokenReqDTO.getClientId());
		      }
	          
	          return tokenRespDTO;
	        }
	      }
	      catch (Exception e)
	      {
	        if (log.isDebugEnabled()) {
	          log.debug("Error while getting existing token for client id : " + oAuth2AccessTokenReqDTO.getClientId());
	          log.error(e);
	        }
	      }
	      if (log.isDebugEnabled()) {
	        log.debug("Issuing a new access token for client id : " + consumerKey + " AuthorizedUser : " + authorizedUser);
	      }
	      String accessToken;
	      try
	      {
		     if (log.isDebugEnabled()) {
			    log.debug("Generating new access token");
			}
	        accessToken = this.oauthIssuerImpl.accessToken();
	      }
	      catch (OAuthSystemException e)
	      {
	        throw new IdentityOAuth2Exception("Error when generating the token", e);
	      }

	      Timestamp timestamp = new Timestamp(new Date().getTime());
	      
	      long validityPeriod = OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds();
	      
	      long callbackValidityPeriod = tokReqMsgCtx.getValidityPeriod();
	      if ((callbackValidityPeriod != -1L) && (callbackValidityPeriod > 0L)) {
	        validityPeriod = callbackValidityPeriod;
	      }
	      AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, tokReqMsgCtx.getAuthorizedUser(), tokReqMsgCtx.getScope(), timestamp, validityPeriod, tokenType);
	      
	      accessTokenDO.setRefreshToken(null);
	      accessTokenDO.setTokenState("ACTIVE");
	      accessTokenDO.setAccessToken(accessToken);
	      accessTokenDO.setTenantID(tokReqMsgCtx.getTenantID());
	      
	      if (log.isDebugEnabled()) {
			    log.debug("Attempting to store access token in database");
			}
	      this.tokenMgtDAO.storeAccessToken(accessToken, oAuth2AccessTokenReqDTO.getClientId(), accessTokenDO, userStoreDomain);
	      
	      if (log.isDebugEnabled()) {
	        log.debug("Persisted an access token with Client id : " + oAuth2AccessTokenReqDTO.getClientId() + " authorized user : " + tokReqMsgCtx.getAuthorizedUser() + " timestamp : " + timestamp + " validity period : " + validityPeriod + " scope : " + OAuth2Util.buildScopeString(tokReqMsgCtx.getScope()) + " Token State : " + "ACTIVE");
	      }
	      
	      if (this.cacheEnabled)
	      {
	        this.oauthCache.addToCache(cacheKey, accessTokenDO);
	        if (log.isDebugEnabled()) {
	          log.debug("Access Token info was added to the cache for the client id : " + oAuth2AccessTokenReqDTO.getClientId());
	        }
	      }
	      OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
	      tokenRespDTO.setAccessToken(accessToken);
	      tokenRespDTO.setExpiresIn(OAuth2Util.getTokenExpireTimeMillis(accessTokenDO) / 1000L);
	      
	      if (log.isDebugEnabled()) {
			    log.debug("Returned access token to client");
			}
	      
	      return tokenRespDTO;
	    }
	  }
	  
	  public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
	    throws IdentityOAuth2Exception
	  {
	    OAuthCallback authzCallback = new OAuthCallback(tokReqMsgCtx.getAuthorizedUser(), tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_TOKEN);
	    
	    authzCallback.setRequestedScope(tokReqMsgCtx.getScope());
	    if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString())) {
	      authzCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(OAuthConstants.OAUTH_SAML2_BEARER_GRANT_ENUM.toString()));
	    } else if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString())) {
	      authzCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(OAuthConstants.OAUTH_IWA_NTLM_GRANT_ENUM.toString()));
	    } else {
	      authzCallback.setGrantType(org.apache.amber.oauth2.common.message.types.GrantType.valueOf(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().toUpperCase()));
	    }
	    this.callbackManager.handleCallback(authzCallback);
	    tokReqMsgCtx.setValidityPeriod(authzCallback.getValidityPeriod());
	    return authzCallback.isAuthorized();
	  }
	  
	  public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
	    throws IdentityOAuth2Exception
	  {
	    OAuthCallback scopeValidationCallback = new OAuthCallback(tokReqMsgCtx.getAuthorizedUser(), tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_TOKEN);
	    
	    scopeValidationCallback.setRequestedScope(tokReqMsgCtx.getScope());
	    if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString())) {
	      scopeValidationCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(OAuthConstants.OAUTH_SAML2_BEARER_GRANT_ENUM.toString()));
	    } else if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString())) {
	      scopeValidationCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(OAuthConstants.OAUTH_IWA_NTLM_GRANT_ENUM.toString()));
	    } else {
	      scopeValidationCallback.setGrantType(org.apache.amber.oauth2.common.message.types.GrantType.valueOf(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().toUpperCase()));
	    }
	    this.callbackManager.handleCallback(scopeValidationCallback);
	    tokReqMsgCtx.setValidityPeriod(scopeValidationCallback.getValidityPeriod());
	    tokReqMsgCtx.setScope(scopeValidationCallback.getApprovedScope());
	    return scopeValidationCallback.isValidScope();
	  }
	}