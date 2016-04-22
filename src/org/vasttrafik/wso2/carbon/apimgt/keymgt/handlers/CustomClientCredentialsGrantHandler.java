package org.vasttrafik.wso2.carbon.apimgt.keymgt.handlers;

import org.wso2.carbon.apimgt.keymgt.ScopesIssuer;
import org.wso2.carbon.apimgt.keymgt.util.APIKeyMgtDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;
import java.util.Arrays;

import org.vasttrafik.wso2.carbon.identity.oauth2.token.handlers.grant.ClientCredentialsGrantHandler;

public class CustomClientCredentialsGrantHandler
extends ClientCredentialsGrantHandler
{
@SuppressWarnings("unused")
private static final String VALIDITY_PERIOD = "validity_period";

public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
{
  RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
  if (parameters == null) {
    return true;
  }
  for (RequestParameter parameter : parameters) {
    if (("validity_period".equals(parameter.getKey())) && 
      (parameter.getValue() != null) && (parameter.getValue().length > 0))
    {
      long validityPeriod = Long.valueOf(parameter.getValue()[0]).longValue();
      
      tokReqMsgCtx.setValidityPeriod(validityPeriod);
    }
  }
  return true;
}

public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
  throws IdentityOAuth2Exception
{
  boolean validateResult = super.validateGrant(tokReqMsgCtx);
  AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
  String username = user.getUserName();
  user.setUserName(username);
  tokReqMsgCtx.setAuthorizedUser(user);
  
  return validateResult;
}

public boolean issueRefreshToken()
  throws IdentityOAuth2Exception
{
  return super.issueRefreshToken();
}

public boolean isOfTypeApplicationUser()
  throws IdentityOAuth2Exception
{
  return super.isOfTypeApplicationUser();
}

@SuppressWarnings({ "rawtypes", "unchecked" })
public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
{
  boolean state = ScopesIssuer.getInstance().setScopes(tokReqMsgCtx);
  if (state)
  {
    String[] scopes = tokReqMsgCtx.getScope();
    
    String applicationScope = APIKeyMgtDataHolder.getApplicationTokenScope();
    if (scopes != null)
    {
      ArrayList<String> scopeList = new ArrayList(scopes.length);
      scopeList.addAll(Arrays.asList(scopes));
      if (!scopeList.contains(applicationScope))
      {
        scopeList.add(applicationScope);
        tokReqMsgCtx.setScope((String[])scopeList.toArray(new String[scopeList.size()]));
      }
    }
  }
  return state;
}
}
