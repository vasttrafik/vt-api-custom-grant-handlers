package org.vasttrafik.wso2.carbon.apimgt.keymgt.handlers;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.vasttrafik.wso2.carbon.apimgt.keymgt.util.CustomAPIKeyMgtUtil;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.keymgt.token.TokenGenerator;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.apimgt.keymgt.handlers.AbstractKeyValidationHandler;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.util.APIKeyMgtDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;

public class CustomDefaultKeyValidationHandler extends AbstractKeyValidationHandler {
  private static final Log log = LogFactory.getLog(CustomDefaultKeyValidationHandler.class);

  private ApiMgtDAO dao = ApiMgtDAO.getInstance();
  private TokenMgtDAO tokenMgtDAO = null;

  public CustomDefaultKeyValidationHandler() {
    log.info(getClass().getName() + " Initialised");
  }

  public boolean validateToken(TokenValidationContext validationContext) throws APIKeyMgtException {

    if (log.isDebugEnabled())
      log.debug(validationContext.getContext() + " " + validationContext.getVersion() + " " + validationContext.getAccessToken());

    if (validationContext.isCacheHit()) {
      APIKeyValidationInfoDTO infoDTO = validationContext.getValidationInfoDTO();
      
      boolean tokenExpired = APIUtil.isAccessTokenExpired(infoDTO);
      if (tokenExpired) {
        infoDTO.setAuthorized(false);
        infoDTO.setValidationStatus(900901);
        if (log.isDebugEnabled())
          log.debug("Token " + validationContext.getAccessToken() + " expired.");
        return false;
      }
      return true;
    }
    AccessTokenInfo tokenInfo = new AccessTokenInfo();
    try {

      String actualVersion = validationContext.getVersion();
      if ((actualVersion != null) && (actualVersion.startsWith("_default_"))) {
        actualVersion = actualVersion.split("_default_")[1];
      }
      
      if (APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
        if (log.isDebugEnabled())
          log.debug("Checking if " + validationContext.getAccessToken() + " exists in cache properties in order to use it for token validation");

        APIKeyValidationInfoDTO infoDTO = CustomAPIKeyMgtUtil.getFromCustomKeyManagerCache(validationContext.getAccessToken());

        if (infoDTO != null) {
          if (log.isDebugEnabled())
            log.debug("Found API Key Validation Info DTO in key cache, returning");

          infoDTO.setAuthorized(true);
          infoDTO.setValidationStatus(0);
          
          validationContext.setValidationInfoDTO(infoDTO);
          
          boolean tokenExpired = APIUtil.isAccessTokenExpired(infoDTO);
          if (tokenExpired) {
            infoDTO.setAuthorized(false);
            infoDTO.setValidationStatus(900901);
            if (log.isDebugEnabled())
              log.debug("Token " + validationContext.getAccessToken() + " expired.");
            return false;
          }
          return true;
        }
      }
      if (log.isDebugEnabled())
        log.debug("No match found in key cache cache for " + validationContext.getAccessToken() + " token, returning to normal handling");

      try {
    	  
    	  if(tokenMgtDAO == null) {
    		  tokenMgtDAO = new TokenMgtDAO();
    	  }

    	  AccessTokenDO accessTokenDO = tokenMgtDAO.retrieveAccessToken(validationContext.getAccessToken(), false);
          
          if(accessTokenDO != null) {
            tokenInfo.setTokenValid(true);
            tokenInfo.setEndUserName(accessTokenDO.getAuthzUser().getUserName());
            tokenInfo.setConsumerKey(accessTokenDO.getConsumerKey());
            
            if(accessTokenDO.getValidityPeriod() == -2L || accessTokenDO.getValidityPeriod() == Long.MAX_VALUE) {
            	tokenInfo.setValidityPeriod(Long.MAX_VALUE);
            } else {
            	tokenInfo.setValidityPeriod(accessTokenDO.getValidityPeriod() * 1000L);
            }

            tokenInfo.setIssuedTime(accessTokenDO.getIssuedTime().getTime());
            tokenInfo.setScope(accessTokenDO.getScope());
            tokenInfo.setApplicationToken(true); // Always assume application token
            
          } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return false;
          }
          
        } catch (IdentityOAuth2Exception e) {
          log.error("Error while obtaining Token Metadata from Database", e);
          throw new APIKeyMgtException("Error while obtaining Token Metadata from Database");
        }
      
      validationContext.setTokenInfo(tokenInfo);

      APIKeyValidationInfoDTO apiKeyValidationInfoDTO = new APIKeyValidationInfoDTO();
      validationContext.setValidationInfoDTO(apiKeyValidationInfoDTO);
      if (!tokenInfo.isTokenValid()) {
        apiKeyValidationInfoDTO.setAuthorized(false);
        if (tokenInfo.getErrorcode() > 0) {
          apiKeyValidationInfoDTO.setValidationStatus(tokenInfo.getErrorcode());
        } else {
          apiKeyValidationInfoDTO.setValidationStatus(900900);
        }
        return false;
      }
      apiKeyValidationInfoDTO.setAuthorized(tokenInfo.isTokenValid());
      apiKeyValidationInfoDTO.setEndUserName(tokenInfo.getEndUserName());
      apiKeyValidationInfoDTO.setConsumerKey(tokenInfo.getConsumerKey());
      apiKeyValidationInfoDTO.setIssuedTime(tokenInfo.getIssuedTime());
      
      apiKeyValidationInfoDTO.setValidityPeriod(tokenInfo.getValidityPeriod());
      
      if (tokenInfo.getScopes() != null) {
        Set<String> scopeSet = new HashSet<String>(Arrays.asList(tokenInfo.getScopes()));
        apiKeyValidationInfoDTO.setScopes(scopeSet);
      }
      
      
      boolean tokenExpired = APIUtil.isAccessTokenExpired(apiKeyValidationInfoDTO);
      if (tokenExpired) {
    	tokenInfo.setTokenValid(false);
    	apiKeyValidationInfoDTO.setAuthorized(false);
    	apiKeyValidationInfoDTO.setValidationStatus(900901);
        if (log.isDebugEnabled())
          log.debug("Token " + validationContext.getAccessToken() + " expired.");
      }

      if (tokenInfo.isTokenValid() && APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
        if (log.isDebugEnabled())
          log.debug("Putting API Key Validation DTO in cache for cache key: " + validationContext.getAccessToken());

        CustomAPIKeyMgtUtil.writeToCustomKeyManagerCache(validationContext.getAccessToken(), apiKeyValidationInfoDTO);
      }

    } catch (Exception e) {
      log.error("Error while obtaining Token Metadata from Authorization Server", e);
      throw new APIKeyMgtException("Error while obtaining Token Metadata from Authorization Server");
    }
    
    return tokenInfo.isTokenValid();
  }

  @Override
  public boolean validateScopes(TokenValidationContext validationContext) throws APIKeyMgtException {
	    
	    if (validationContext.isCacheHit()) {
	      return true;
	    }
	    OAuth2ScopeValidator scopeValidator = OAuthServerConfiguration.getInstance().getoAuth2ScopeValidator();

	    APIKeyValidationInfoDTO apiKeyValidationInfoDTO = validationContext.getValidationInfoDTO();
	    if (apiKeyValidationInfoDTO == null) {
	      throw new APIKeyMgtException("Key Validation information not set");
	    }
	    String[] scopes = null;
	    Set<String> scopesSet = apiKeyValidationInfoDTO.getScopes();
	    if ((scopesSet != null) && (!scopesSet.isEmpty())) {
	      scopes = (String[]) scopesSet.toArray(new String[scopesSet.size()]);
	      if ((log.isDebugEnabled()) && (scopes != null)) {
	        StringBuffer scopeList = new StringBuffer();
	        for (String scope : scopes) {
	          scopeList.append(scope + ",");
	        }
	        scopeList.deleteCharAt(scopeList.length() - 1);
	        if (log.isDebugEnabled())
	          log.debug("Scopes allowed for token : " + validationContext.getAccessToken() + " : " + scopeList.toString());
	      }
	    }
	    AuthenticatedUser user = new AuthenticatedUser();
	    user.setUserName(apiKeyValidationInfoDTO.getEndUserName());
	    AccessTokenDO accessTokenDO = new AccessTokenDO(apiKeyValidationInfoDTO.getConsumerKey(), user, scopes, null, null, apiKeyValidationInfoDTO.getValidityPeriod(),
	        apiKeyValidationInfoDTO.getValidityPeriod(), apiKeyValidationInfoDTO.getType());

	    accessTokenDO.setAccessToken(validationContext.getAccessToken());

	    String actualVersion = validationContext.getVersion();
	    if ((actualVersion != null) && (actualVersion.startsWith("_default_"))) {
	      actualVersion = actualVersion.split("_default_")[1];
	    }
	    String resource = validationContext.getContext() + "/" + actualVersion + validationContext.getMatchingResource() + ":" + validationContext.getHttpVerb();

	    try {
	      if (scopeValidator != null) {
	        if (scopeValidator.validateScope(accessTokenDO, resource)) {
	          
	          return true;
	        }
	        apiKeyValidationInfoDTO.setAuthorized(false);
	        apiKeyValidationInfoDTO.setValidationStatus(900910);
	      }
	    } catch (IdentityOAuth2Exception e) {
	      log.error("ERROR while validating token scope " + e.getMessage());
	      apiKeyValidationInfoDTO.setAuthorized(false);
	      apiKeyValidationInfoDTO.setValidationStatus(900910);
	    }
	    
	    return false;
	  }

  public boolean validateSubscription(TokenValidationContext validationContext) throws APIKeyMgtException {
    
    if ((validationContext == null) || (validationContext.getValidationInfoDTO() == null)) {
      return false;
    }
    if (validationContext.isCacheHit()) {
      return true;
    }
    APIKeyValidationInfoDTO dto = validationContext.getValidationInfoDTO();
    if (validationContext.getTokenInfo() != null) {
      if (validationContext.getTokenInfo().isApplicationToken()) {
        dto.setUserType("APPLICATION");
      } else {
        dto.setUserType("APPLICATION_USER");
      }
      AccessTokenInfo tokenInfo = validationContext.getTokenInfo();
      if (!hasTokenRequiredAuthLevel(validationContext.getRequiredAuthenticationLevel(), tokenInfo)) {
        dto.setAuthorized(false);
        dto.setValidationStatus(900905);
        return false;
      }
    }
    boolean state = false;
    try {
      if (log.isDebugEnabled()) {
        log.debug("Before validating subscriptions : " + dto);
        log.debug("Validation Info : { context : " + validationContext.getContext() + " , " + "version : " + validationContext.getVersion() + " , consumerKey : " + dto.getConsumerKey() + " }");
      }

      String actualVersion = validationContext.getVersion();
      if ((actualVersion != null) && (actualVersion.startsWith("_default_"))) {
        actualVersion = actualVersion.split("_default_")[1];
      }

      if (APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
        if (log.isDebugEnabled()) {
          log.debug("Looking up API Key Validation Info DTO in in key cache for key: " + validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey());
        }

        APIKeyValidationInfoDTO infoDTO = CustomAPIKeyMgtUtil.getFromCustomKeyManagerCache(validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey());

        if (infoDTO != null) {
          if (log.isDebugEnabled())
            log.debug("Found API Key validation Info DTO in key cache, returning");

          /* Copy info from previous DTO for this context, version and consumer key */
          dto.setTier(infoDTO.getTier());
          dto.setSubscriber(infoDTO.getSubscriber());
          dto.setApplicationId(infoDTO.getApplicationId());
          dto.setApiName(infoDTO.getApiName());
          dto.setApiPublisher(infoDTO.getApiPublisher());
          dto.setApplicationName(infoDTO.getApplicationName());
          dto.setApplicationTier(infoDTO.getApplicationTier());
          dto.setType(infoDTO.getType());
          dto.setAuthorizedDomains(infoDTO.getAuthorizedDomains());

          return true;
        }
      }

      state = this.dao.validateSubscriptionDetails(validationContext.getContext(), validationContext.getVersion(), dto.getConsumerKey(), dto);
      if (state) {
    	  
    	  dto.setAuthorizedDomains(Arrays.asList(new String[] {"ALL"})); // Allow all domains

        if (APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
          if (log.isDebugEnabled())
            log.debug("Putting subscription DTO in cache for cache key: " + validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey());

          CustomAPIKeyMgtUtil.writeToCustomKeyManagerCache((validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey()), dto);

        }

      }
      if (log.isDebugEnabled())
        log.debug("After validating subscriptions : " + dto);

    } catch (APIManagementException e) {
      log.error("Error Occurred while validating subscription.", e);
    }
    
    return state;
  }

  protected void setTokenType(AccessTokenInfo tokenInfo) {}

  protected boolean hasTokenRequiredAuthLevel(String authScheme, AccessTokenInfo tokenInfo) {
    if ((authScheme == null) || (authScheme.isEmpty()) || (tokenInfo == null)) {
      return false;
    }
    if ("Application".equals(authScheme)) {
      return tokenInfo.isApplicationToken();
    }
    if ("Application_User".equals(authScheme)) {
      return !tokenInfo.isApplicationToken();
    }
    return true;
  }
  
  public boolean generateConsumerToken(TokenValidationContext validationContext)
      throws APIKeyMgtException
    {
    
      TokenGenerator generator = APIKeyMgtDataHolder.getTokenGenerator();
      try
      {
    	String jwt = generator.generateToken(validationContext);
        validationContext.getValidationInfoDTO().setEndUserToken(jwt);
        
        return true;
      }
      catch (APIManagementException e)
      {
        log.error("Error occurred while generating JWT. ", e);
      }
      return false;
    }
}
