package org.vasttrafik.cache.properties;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CacheProperties {

  protected static final Logger logger = LoggerFactory.getLogger(CacheProperties.class);

  private static ConcurrentHashMap<String, List<String>> VALUES = new ConcurrentHashMap<String, List<String>>();
  private static HashSet<String> CONTEXT_VERSIONS = new HashSet<String>();
  private static DateTime LAST_UPDATED = new DateTime();

  static {

    updateCacheProperties();

  }

  public static boolean containsConsumerKey(String consumerKey) {
    
    checkNeedsUpdate();

    return VALUES.containsKey(consumerKey);

  }

  public static boolean containsContextVersion(String contextVersion) {
    
    checkNeedsUpdate();

    return CONTEXT_VERSIONS.contains(contextVersion);

  }

  public static List<String> getContextVersions(String consumerKey) {
    
    checkNeedsUpdate();

    return VALUES.get(consumerKey);
  }
  
  private static void checkNeedsUpdate() {
    
    if (LAST_UPDATED.plusMinutes(1).isBeforeNow())
      updateCacheProperties();  
  }

  private static void updateCacheProperties() {

    try {
      CacheProperties.LAST_UPDATED = new DateTime();

      ConcurrentHashMap<String, List<String>> tempValues = new ConcurrentHashMap<String, List<String>>();
      HashSet<String> tempContextVersions = new HashSet<String>();

      // Get the contents of the file
      BufferedReader reader = new BufferedReader(new FileReader(new File(System.getProperty("carbon.home") + "/cache.properties").getAbsolutePath()));

      // A line from the cache properties file
      String inputLine = null;

      while ((inputLine = reader.readLine()) != null) {
        StringTokenizer st = new StringTokenizer(inputLine, ";");
        
        String consumerKey = st.nextToken();
        
        ArrayList<String> list = new ArrayList<String>();
        while(st.hasMoreTokens()) {
          String contextVersion = st.nextToken();
          list.add(contextVersion);
          tempContextVersions.add(contextVersion);
        }

        tempValues.put(consumerKey, list);

      }
      reader.close();

      VALUES = tempValues;
      CONTEXT_VERSIONS = tempContextVersions;

      if(logger.isDebugEnabled()) 
        logger.debug("Read " + tempValues.size() + " consumer keys and " + tempContextVersions.size() + " context versions into cache properties");

    } catch (Exception e) {
      logger.error("Problem reading cache properties from  " + System.getProperty("carbon.home") + "/cache.properties", e);
    }
  }

}
