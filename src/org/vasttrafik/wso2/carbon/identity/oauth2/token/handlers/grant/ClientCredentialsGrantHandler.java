package org.vasttrafik.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

public class ClientCredentialsGrantHandler
extends AbstractAuthorizationGrantHandler
{
@SuppressWarnings("unused")
private static Log log = LogFactory.getLog(ClientCredentialsGrantHandler.class);

public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
  throws IdentityOAuth2Exception
{
  if (!super.validateGrant(tokReqMsgCtx)) {
    return false;
  }
  tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
  return true;
}

public boolean issueRefreshToken()
  throws IdentityOAuth2Exception
{
  return false;
}

public boolean isOfTypeApplicationUser()
  throws IdentityOAuth2Exception
{
  return false;
}
}

