package org.vasttrafik.wso2.carbon.apimgt.keymgt.handlers;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.vasttrafik.cache.properties.CacheProperties;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.apimgt.keymgt.handlers.AbstractKeyValidationHandler;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.util.APIKeyMgtDataHolder;
import org.wso2.carbon.apimgt.keymgt.util.APIKeyMgtUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;

public class CustomDefaultKeyValidationHandler extends AbstractKeyValidationHandler {
  private static final Log log = LogFactory.getLog(CustomDefaultKeyValidationHandler.class);

  private ApiMgtDAO dao = new ApiMgtDAO();

  public CustomDefaultKeyValidationHandler() {
    log.info(getClass().getName() + " Initialised");
  }

  public boolean validateToken(TokenValidationContext validationContext) throws APIKeyMgtException {

    if (log.isDebugEnabled())
      log.debug(validationContext.getContext() + " " + validationContext.getVersion() + " " + validationContext.getAccessToken());

    if (validationContext.isCacheHit()) {
      APIKeyValidationInfoDTO infoDTO = validationContext.getValidationInfoDTO();

      checkClientDomainAuthorized(infoDTO, validationContext.getClientDomain());
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
    AccessTokenInfo tokenInfo = null;
    try {

      String actualVersion = validationContext.getVersion();
      if ((actualVersion != null) && (actualVersion.startsWith("_default_"))) {
        actualVersion = actualVersion.split("_default_")[1];
      }

      if (log.isDebugEnabled())
        log.debug("Checking if " + validationContext.getContext() + "/" + actualVersion + " exists in cache properties in order to convert Access Token DO to Validation Info DTO");

      if (CacheProperties.containsContextVersion(validationContext.getContext() + "/" + actualVersion) && OAuthServerConfiguration.getInstance().isCacheEnabled()) {
        if (log.isDebugEnabled())
          log.debug("Context and version found in cache properties. Attempting to lookup cached Access Token DO for context version: " + validationContext.getContext() + "/" + actualVersion
              + " in oAuthCache");

        AccessTokenDO accessTokenDO =
            (AccessTokenDO) OAuthCache.getInstance().getValueFromCache(new OAuthCacheKey(validationContext.getContext() + "/" + actualVersion + validationContext.getAccessToken()));
        if (accessTokenDO != null) {
          if (log.isDebugEnabled())
            log.debug("Found cached Access Token DO in oAuth cache. Converting to Validation Info DTO");

          tokenInfo = new AccessTokenInfo();
          tokenInfo.setTokenValid(true);
          tokenInfo.setEndUserName(accessTokenDO.getAuthzUser().getUserName());
          tokenInfo.setConsumerKey(accessTokenDO.getConsumerKey());
          tokenInfo.setValidityPeriod(accessTokenDO.getValidityPeriod() * 1000L);
          tokenInfo.setIssuedTime((accessTokenDO != null ? accessTokenDO.getIssuedTime().getTime() : System.currentTimeMillis()));
          tokenInfo.setScope(accessTokenDO.getScope());
          tokenInfo.setApplicationToken(true);

          validationContext.setTokenInfo(tokenInfo);

          APIKeyValidationInfoDTO apiKeyValidationInfoDTO = new APIKeyValidationInfoDTO();
          validationContext.setValidationInfoDTO(apiKeyValidationInfoDTO);

          apiKeyValidationInfoDTO.setAuthorized(tokenInfo.isTokenValid());
          apiKeyValidationInfoDTO.setEndUserName(tokenInfo.getEndUserName());
          apiKeyValidationInfoDTO.setConsumerKey(tokenInfo.getConsumerKey());
          apiKeyValidationInfoDTO.setIssuedTime(tokenInfo.getIssuedTime());
          apiKeyValidationInfoDTO.setValidityPeriod(tokenInfo.getValidityPeriod());
          if (tokenInfo.getScopes() != null) {
            Set<String> scopeSet = new HashSet<String>(Arrays.asList(tokenInfo.getScopes()));
            apiKeyValidationInfoDTO.setScopes(scopeSet);
          }

          if (log.isDebugEnabled())
            log.debug("Converted cached Access Token DO to Validation Info DTO, returning");

          return true;
        }
      }

      if (log.isDebugEnabled())
        log.debug("No match found in oAuth cache for (" + validationContext.getContext() + "/" + actualVersion + validationContext.getAccessToken() + ") , returning to normal handling");

      if (log.isDebugEnabled())
        log.debug("Checking if " + validationContext.getContext() + "/" + actualVersion + " exists in cache properties in order to use it for token validation");
      if (CacheProperties.containsContextVersion(validationContext.getContext() + "/" + actualVersion) && APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
        if (log.isDebugEnabled()) {
          log.debug("Context and version found in cache properties. Attempting to lookup cached Access Token DO for key: " + validationContext.getContext() + "/" + actualVersion
              + validationContext.getAccessToken() + " in key cache");
        }

        APIKeyValidationInfoDTO infoDTO = APIKeyMgtUtil.getFromKeyManagerCache((validationContext.getContext() + "/" + actualVersion + validationContext.getAccessToken()));

        if (infoDTO != null) {
          if (log.isDebugEnabled())
            log.debug("Found API Key Validation Info DTO in key cache, returning");

          validationContext.setValidationInfoDTO(infoDTO);
          return true;
        }
      }

      tokenInfo = KeyManagerHolder.getKeyManagerInstance().getTokenMetaData(validationContext.getAccessToken());
      if (tokenInfo == null) {
        return false;
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

      if (tokenInfo.isTokenValid() && CacheProperties.containsContextVersion(validationContext.getContext() + actualVersion) && APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
        if (log.isDebugEnabled())
          log.debug("Putting API Key Validation DTO in cache for cache key: " + validationContext.getContext() + "/" + actualVersion + tokenInfo.getAccessToken());

        APIKeyMgtUtil.writeToKeyManagerCache((validationContext.getContext() + "/" + actualVersion + tokenInfo.getAccessToken()), apiKeyValidationInfoDTO);
      }

    } catch (APIManagementException e) {
      log.error("Error while obtaining Token Metadata from Authorization Server", e);
      throw new APIKeyMgtException("Error while obtaining Token Metadata from Authorization Server");
    }
    return tokenInfo.isTokenValid();
  }

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

      if (log.isDebugEnabled())
        log.debug("Checking if " + validationContext.getContext() + "/" + actualVersion + " for consumer key " + dto.getConsumerKey() + " exists in cache properties in order to retrieve it for subscription check");
      if (CacheProperties.containsConsumerKey(dto.getConsumerKey()) && CacheProperties.containsContextVersion(validationContext.getContext() + "/" + actualVersion) && APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
        if (log.isDebugEnabled()) {
          log.debug("Looking up API Key Validation Info DTO in in key cache for key: " + validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey());
        }

        APIKeyValidationInfoDTO infoDTO = APIKeyMgtUtil.getFromKeyManagerCache(validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey());

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

          return true;
        }
      }

      state = this.dao.validateSubscriptionDetails(validationContext.getContext(), validationContext.getVersion(), dto.getConsumerKey(), dto);
      if (state) {

        /*
         * dto.setAuthorizedDomains(APIUtil.getListOfAuthorizedDomainsByConsumerKey(
         * validationContext.getTokenInfo().getConsumerKey())); checkClientDomainAuthorized(dto,
         * validationContext.getClientDomain());
         */

        if (log.isDebugEnabled())
          log.debug("Checking if " + validationContext.getContext() + "/" + actualVersion + " for consumer key " + dto.getConsumerKey() + " exists in cache properties in order to store it in cache");
        if (CacheProperties.containsConsumerKey(dto.getConsumerKey()) && CacheProperties.containsContextVersion(validationContext.getContext() + "/" + actualVersion) && APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
          if (log.isDebugEnabled())
            log.debug("Putting subscription DTO in cache for cache key: " + validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey());

          APIKeyMgtUtil.writeToKeyManagerCache((validationContext.getContext() + "/" + actualVersion + dto.getConsumerKey()), dto);

        }

      }
      if (log.isDebugEnabled())
        log.debug("After validating subscriptions : " + dto);

    } catch (APIManagementException e) {
      log.error("Error Occurred while validating subscription.", e);
    }
    return state;
  }

  protected void checkClientDomainAuthorized(APIKeyValidationInfoDTO apiKeyValidationInfoDTO, String clientDomain) throws APIKeyMgtException {
    try {
      APIUtil.checkClientDomainAuthorized(apiKeyValidationInfoDTO, clientDomain);
    } catch (APIManagementException e) {
      log.error("Error while validating client domain", e);
    }
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
}
