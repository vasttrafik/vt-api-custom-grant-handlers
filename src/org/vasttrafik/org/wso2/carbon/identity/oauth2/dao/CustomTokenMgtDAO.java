package org.vasttrafik.org.wso2.carbon.identity.oauth2.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public class CustomTokenMgtDAO extends TokenMgtDAO {

  private final Log log = LogFactory.getLog(CustomTokenMgtDAO.class);

  private static final String IDN_OAUTH2_ACCESS_TOKEN = "IDN_OAUTH2_ACCESS_TOKEN";
  private static final String UTC = "UTC";
  private static TokenPersistenceProcessor persistenceProcessor;
  
  private boolean enablePersist = true;

  Connection connection = IdentityDatabaseUtil.getDBConnection();

  public CustomTokenMgtDAO() {
    super();

    try {
      persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
    } catch (IdentityOAuth2Exception e) {
      log.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextProcessor", e);
      persistenceProcessor = new PlainTextPersistenceProcessor();
    }
    
    if (IdentityUtil.getProperty("JDBCPersistenceManager.TokenPersist.Enable") != null) {
      this.enablePersist = Boolean.parseBoolean(IdentityUtil.getProperty("JDBCPersistenceManager.TokenPersist.Enable"));
    }
  }

  public AccessTokenDO retrieveLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain, String scope, boolean includeExpiredTokens) throws IdentityOAuth2Exception {

    StopWatch stopWatch = new StopWatch();

    Connection connection = IdentityDatabaseUtil.getDBConnection();
    
    boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
    String tenantDomain = authzUser.getTenantDomain();
    String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
    String userDomain = authzUser.getUserStoreDomain();
    if ((userDomain != null)) {
      userDomain.toUpperCase();
    }

    PreparedStatement prepStmt = null;
    ResultSet resultSet = null;
    try {

      // Always assume MSSQL
      
      String sql =  "SELECT TOP 1 ACCESS_TOKEN, REFRESH_TOKEN, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_STATE, USER_TYPE, TOKEN_ID, SUBJECT_IDENTIFIER FROM IDN_OAUTH2_ACCESS_TOKEN WITH ( INDEX(IDN_OAUTH2_ACCESS_TOKEN_IDX1), NOLOCK) WHERE CONSUMER_KEY_ID = (SELECT ID FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY = ?) AND AUTHZ_USER=? AND TOKEN_SCOPE_HASH=? ORDER BY TIME_CREATED DESC";
      //sql += " OPTION (TABLE HINT(IDN_OAUTH2_ACCESS_TOKEN, INDEX(IDN_OAUTH2_ACCESS_TOKEN_IDX1)))";

      if (StringUtils.isNotEmpty(userStoreDomain)) {
        // logic to store access token into different tables when multiple user stores are
        // configured.
        sql = sql.replace(IDN_OAUTH2_ACCESS_TOKEN, IDN_OAUTH2_ACCESS_TOKEN + "_" + userStoreDomain);
      }
      if (!isUsernameCaseSensitive) {
        sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
      }

      String hashedScope = OAuth2Util.hashScopes(scope);
      if (hashedScope == null) {
        sql = sql.replace("TOKEN_SCOPE_HASH=?", "TOKEN_SCOPE_HASH IS NULL");
      }

      prepStmt = connection.prepareStatement(sql);
      prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
      if (isUsernameCaseSensitive) {
        prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain);
      } else {
        prepStmt.setString(2, tenantAwareUsernameWithNoUserDomain.toLowerCase());
      }

      if (hashedScope != null) {
        prepStmt.setString(3, hashedScope);
      }

      if(log.isDebugEnabled()) {
        log.debug(sql);
      }
      
      if(log.isInfoEnabled()) {
        stopWatch.start();      
      }
      
      resultSet = prepStmt.executeQuery();
      connection.commit();
      
      if(log.isInfoEnabled()) {
        stopWatch.stop();
        log.info("Execute query took: " + stopWatch.getTime() + " ms.");
      }

      if (resultSet.next()) {
        boolean returnToken = false;
        String tokenState = resultSet.getString(7);
        if (includeExpiredTokens) {
          if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState) || OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(tokenState)) {
            returnToken = true;
          }
        } else {
          if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState)) {
            returnToken = true;
          }
        }
        if (returnToken) {
          String accessToken = persistenceProcessor.getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
          String refreshToken = null;
          if (resultSet.getString(2) != null) {
            refreshToken = persistenceProcessor.getPreprocessedRefreshToken(resultSet.getString(2));
          }
          long issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC))).getTime();
          long refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone.getTimeZone(UTC))).getTime();
          long validityPeriodInMillis = resultSet.getLong(5);
          long refreshTokenValidityPeriodInMillis = resultSet.getLong(6);

          String userType = resultSet.getString(8);
          String tokenId = resultSet.getString(9);
          String subjectIdentifier = resultSet.getString(10);
          // data loss at dividing the validity period but can be neglected
          AuthenticatedUser user = new AuthenticatedUser();
          user.setUserName(tenantAwareUsernameWithNoUserDomain);
          user.setTenantDomain(tenantDomain);
          user.setUserStoreDomain(userDomain);
          user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
          AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, user, OAuth2Util.buildScopeArray(scope), new Timestamp(issuedTime), new Timestamp(refreshTokenIssuedTime),
              validityPeriodInMillis, refreshTokenValidityPeriodInMillis, userType);
          accessTokenDO.setAccessToken(accessToken);
          accessTokenDO.setRefreshToken(refreshToken);
          accessTokenDO.setTokenState(tokenState);
          accessTokenDO.setTokenId(tokenId);
          return accessTokenDO;
        }
      }
      return null;
    } catch (SQLException e) {
      String errorMsg = "Error occurred while trying to retrieve latest 'ACTIVE' " + "access token for Client ID : " + consumerKey + ", User ID : " + authzUser + " and  Scope : " + scope;
      if (includeExpiredTokens) {
        errorMsg = errorMsg.replace("ACTIVE", "ACTIVE or EXPIRED");
      }
      throw new IdentityOAuth2Exception(errorMsg, e);
    } finally {
      IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
    }
  }
  
  public void storeAccessTokens(List<AccessTokenDO> accessTokenDOList)
      throws IdentityOAuth2Exception
    {
    
    }

}
