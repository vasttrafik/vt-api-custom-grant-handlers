# vt-api-custom-grant-handlers

Enhancements to Grant handlers and validators for WSO2 API Manager (Key Manager).

## Client Credentials Grand Handler
This package includes a ClientCredentialsGrantHandler that can be used as a replacement of the supplied WSO2 one.

This handler was written to offload database reads/writes as was noted a problem during heavy load. All created access tokens and information is stored in a cache which is used during key validation (In CustomDefaultKeyValidationHandler). Writes to the database is done in batches instead of one-by-one. In order to make sure all keys are written to the database if the server is taken offline, the package includes a shutdownhook which completes when all keys are correctly written. The database code is specifically written for MS SQL and if another database is used, the SQL code needs to be updated.

To use the grant handler replace the specified handler in <WSO2_HOME>/repository/conf/identity/identity.xml

```
<SupportedGrantType>
  <GrantTypeName>client_credentials</GrantTypeName>
  <GrantTypeHandlerImplClass>org.vasttrafik.wso2.carbon.apimgt.keymgt.handlers.CustomClientCredentialsGrantHandler</GrantTypeHandlerImplClass>
</SupportedGrantType>
```

## Key Validation Handler
To go along with the credentials grant handler is a key validation handler which firstly checks to see if the information for a key is available in the cache. If it is, it'll use that information and not look into the database.

To use the key validation handler replace the specified handler class in <WSO2_HOME>/repository/conf/api-manager.xml

```
<KeyValidationHandlerClassName>org.vasttrafik.wso2.carbon.apimgt.keymgt.handlers.CustomDefaultKeyValidationHandler</KeyValidationHandlerClassName>
```

## Installation

Place the target jar file in <WSO2_HOME>/repository/components/dropins