package org.vasttrafik.wso2.carbon.caching.shutdown;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.vasttrafik.wso2.carbon.apimgt.keymgt.util.CustomAPIKeyMgtUtil;
import org.wso2.carbon.core.ServerShutdownHandler;

public class CustomAccessTokenCacheShutdownManager implements ServerShutdownHandler {

	private static Log log = LogFactory.getLog(CustomAccessTokenCacheShutdownManager.class);
	
	@Override
	public void invoke() {
		CustomAPIKeyMgtUtil.runShutdownHook();
		log.info("CustomAccessTokenCacheShutdownManager shutdown hook completed");
	}

}
