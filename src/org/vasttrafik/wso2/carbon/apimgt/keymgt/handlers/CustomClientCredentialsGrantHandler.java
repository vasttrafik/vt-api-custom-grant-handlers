package org.vasttrafik.wso2.carbon.apimgt.keymgt.handlers;

import org.wso2.carbon.apimgt.keymgt.handlers.ScopesIssuer;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.vasttrafik.wso2.carbon.identity.oauth2.token.handlers.grant.ClientCredentialsGrantHandler;

public class CustomClientCredentialsGrantHandler extends ClientCredentialsGrantHandler
{
	  public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
	    throws IdentityOAuth2Exception
	  {
	    return super.validateGrant(tokReqMsgCtx);
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
	  
	  public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
	  {
	    ScopesIssuer scopesIssuer = new ScopesIssuer();
	    return scopesIssuer.setScopes(tokReqMsgCtx);
	  }
	}
