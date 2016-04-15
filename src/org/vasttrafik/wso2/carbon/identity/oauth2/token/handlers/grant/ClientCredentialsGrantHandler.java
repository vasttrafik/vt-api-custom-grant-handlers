package org.vasttrafik.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

public class ClientCredentialsGrantHandler
  extends AbstractAuthorizationGrantHandler
{
  private static Log log = LogFactory.getLog(ClientCredentialsGrantHandler.class);
  
  public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
    throws IdentityOAuth2Exception
  {
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

