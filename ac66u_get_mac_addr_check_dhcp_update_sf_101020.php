<?php

// README: 
// Script purpose: to update data in SF regarding DHCP config and MAC address. It updates only data in the Client_IP_Detail__c Salesforce Object. 
// As of 10/16/2020, it tries to contact all routers that: 1. have not been contacted in 7 or more days, 2. have DHCP set to False or null, 3. have 
// no MAC address configured. Of these that it contacts, it only updates the SF record if it is able to successfully get info from the ASUS router. 
// This way it does not interfere with manual entries which might be done by technicians. A record of when the MAC was last updated is keps locally
// on this server, as well as in the Client_IP_Detail__c object, visible to the technicians so they understand they can convert it to DHCP. This 
// script does not convert to DHCP. It is meant to provide assistance to streamline the process. Eventually it will not be needed as we phase out 
// the ASUS routers. NOTE: this script depends on SSH to be running on the ASUS router and that the source IP from which the script runs must be 
// allowed by the router's config. 



/////////////////////////////////////////// Includes //////////////////////////////////////////////
require (__DIR__ . '/../commonDirLocation.php');
//require_once (__DIR__ . '/../autoload.php');
require_once (COMMON_PHP_DIR . '/vendor/autoload.php');
$loader = new \Composer\Autoload\ClassLoader();
$loader->addPsr4('phpseclib\\', realpath(COMMON_PHP_DIR . '/vendor/phpseclib/phpseclib/phpseclib'));
$loader->register();

use phpseclib\Crypt\RSA;
use phpseclib\Net\SSH2;
require_once (COMMON_PHP_DIR . '/get_last_hop.php'); //alternative method of getting the MAC address
require_once (COMMON_PHP_DIR . '/production.userAuth.php');
require_once (COMMON_PHP_DIR . '/SlackMessagePost.php');
require_once (COMMON_PHP_DIR . '/creds.php');
require_once (COMMON_PHP_DIR . '/checkOrgID.php');
require_once (COMMON_PHP_DIR . '/respond.php');
require_once (COMMON_PHP_DIR . '/parseNotification.php');
require_once (COMMON_PHP_DIR . '/deleteOldLogs.php');
require_once (COMMON_PHP_DIR . '/checkWait.php');
require_once (COMMON_PHP_DIR . '/writelog.php');
require_once (COMMON_PHP_DIR . '/logTime.php');
require_once (COMMON_PHP_DIR . '/security_check.php');

//////////////////////////////////////// Variables /////////////////////////////////////////////////
date_default_timezone_set('America/Los_Angeles');
ini_set("soap.wsdl_cache_enabled", "0");  // clean WSDL for develop
$f_name = pathinfo(__FILE__)['basename'];
$f_dir = pathinfo(__FILE__)['dirname'];
$rel_path = substr(__FILE__, strlen($_SERVER['DOCUMENT_ROOT']));
$log_dir = '/log/';
$sf_url = 'https://unwired.my.salesforce.com';
$heavy_logging = 1;
$today_obj = new DateTime('now');
$today = $today_obj->format('Y-m-d');
$config_route_prompt = 'admin@RT.*:';
$wsdl = COMMON_PHP_DIR . '/wsdl/production.enterprise.wsdl.xml';


//=================================================== START EXECUTION CODE =========================================================

writelog("\n\n=====================================================================================================\n\n");
log_time();

try {
                                                                                        heavylog("QUERYING SALESFORCE FOR INFO");
  $mySforceConnection = new SforceEnterpriseClient();
  $mySoapClient = $mySforceConnection->createConnection($wsdl);
  $mylogin = $mySforceConnection->login($USERNAME, $PASSWORD);

  $query = "SELECT
    Id
    , IP__c
    , DHCP__c
    , MAC_Address__c
    , Opportunity__c
FROM Client_IP_Detail__c
WHERE
    Opportunity__c IN (
        SELECT Opportunity__c
        FROM Managed_Services__c
        WHERE
            Service_Type__c LIKE '%router%'
            AND Manufacturer_of_CPE__c LIKE '%asus%'
    )
ORDER BY
    Opportunity__c";
  $options = new QueryOptions(2000);  //Set query to return results in chunks
  $mySforceConnection->setQueryOptions($options);
  $done = false;
  $response = $mySforceConnection->query(($query));
  echo "Size of records:  " . $response->size."\n";
  $record_arr=array();
  if ($response->size > 0) {
    while (!$done) {
      foreach ($response->records as $record) {
                                                                                            print_r($record);
        if (!(empty($record->Opportunity__c))) {
          $opp_id = $record->Opportunity__c;
          $sf_id = $record->Id;
          $record_arr[$sf_id] = new stdClass();
          $record_arr[$sf_id]->DHCP__c = $record->DHCP__c;
          $record_arr[$sf_id]->IP__c = $record->IP__c;
          if (!filter_var($record_arr[$sf_id]->IP__c, FILTER_VALIDATE_IP)) {
            $msg = $record_arr[$sf_id]->IP__c . " is not valid.";
                                                                                            writelog($msg);
            unset($record_arr[$sf_id]);
            continue;
          }
          $mac_repl_arr = ['-','.',' '];
          $record_arr[$sf_id]->MAC_Address__c = (!empty($record->MAC_Address__c))? strtoupper(str_replace($mac_repl_arr,':',trim($record->MAC_Address__c))) : NULL;
        }
      }
      if ($response->done == true) {
        $done = true;
      } else {
//      echo "***** Get Next Chunk *****\n";
        $response = $mySforceConnection->queryMore($response->queryLocator);
      }
    }
  }
} catch (Exception $e) {
  $msg = "Caught exception: $e";
  $sf_update_arr[0] = new stdClass();
  $sf_update_arr[0]->error_msg = "ERROR: $msg";
                                                                                        writelog("\n$msg\n");
                                                                                        slack("$rel_path :: $msg" , 'mattd');
}

                                                                                        heavylog("DONE QUERYING SALESFORCE");
                                                                                        print_r($record_arr);
                                                                                        print_r("\nOutput record count: " . count($record_arr) . "\n\n");


$success_count = 0;

                                                                                        heavylog("LOADING DATA FROM JSON FILE");
$json_obj = json_decode(file_get_contents('mac_and_dhcp_info.json'));
print_r("\njson_obj: ");
print_r($json_obj);
$info_arr = (array) $json_obj;


                                                                                        heavylog("PARSING JSON AND DETERMINING WHICH ROUTERS TO ATTEMPT TO UPDATE");
try {
  foreach ($record_arr as $sf_id => $record_obj) {
    $need_to_update_sf = False;
    if (isset($info_arr[$sf_id])) {
      $info_obj = $info_arr[$sf_id];
      if (isset($info_obj->MAC_Address__c) OR isset($info_obj->DHCP__c)) {
        if ((preg_match('/([A-F0-9]{2}:){5}[A-F0-9]{2}/i', $record_obj->MAC_Address__c) AND
           ($record_obj->MAC_Address__c !== $info_obj->MAC_Address__c)) OR
           (!isset($info_obj->MAC_Last_Update) OR (strtotime("now") - strtotime($info_obj->MAC_Last_Update)) > (7 * 24 * 60 * 60 ))) {
          $need_to_update_sf = True;
        }
        if ($record_obj->DHCP__c !== 'true') {
          $need_to_update_sf = True;
        } else {

        }
      } else {
        $need_to_update_sf = True;
      }
    } else {
      $need_to_update_sf = True;
    }
    if ($need_to_update_sf) {
      $sf_update_obj = new stdClass();
      $sf_update_obj->Id = $sf_id;
      $sf_update_obj->IP__c = $record_obj->IP__c;
      $to_update_arr[$sf_id] = $sf_update_obj;
    }
  }

                                                                                        heavylog("CONTACTING ASUS ROUTERS TO GET INFO");
    // Use this to bind to a specific IP address. 
    // http://us3.php.net/manual/en/context.socket.php
    /*$opts = array(
      'socket' => array(
        'bindto' => '192.168.2.41:0',
      ),
    );
    $context = stream_context_create($opts);
    $socket = stream_socket_client('tcp://' .$ip_string. ':22', $errno, $errstr, ini_get('default_socket_timeout'), STREAM_CLIENT_CONNECT, $context);
    */
  $sf_update_arr = [];
  $ct = 0;
  foreach ($to_update_arr as $sf_id => $sf_obj) {
    $success = False;
    $ip_string = $sf_obj->IP__c;
    //print_r("\n$ip_string");
    $secure1 = check_for_peer_name_in_ssl_cert($ip_string . ':8443', 'router.asus.com');
    $secure2 = check_for_peer_name_in_ssl_cert($ip_string . ':8443', '192.168.50.1');
    if (!($secure1 OR $secure2)) {
      $msg = "$ip_string seems insecure or could not be contacted. Skipping.";
      //print_r("\n$msg");
      unset($secure1, $secure2);
      continue;
    }
    unset($secure1, $secure2);
    $ssh = new SSH2($ip_string, 22);
    $ssh->setTimeout(2);
    if (!$ssh->login(ASUS_USER, ASUS_PASS)) {
      $msg = "$ip_string - Login Failed";
      //print_r("\n$msg");
                                                                                        writelog($msg);
      continue;
    }
    $ssh->write("\r"); // somehow works around an issue of premature end of connection on cisco IOS

    if ($ssh->read($config_route_prompt)) {
      $new_info_obj = new stdClass();
      $new_info_obj->Id = $sf_id;
      $cmd = "nvram get wan0_proto\r\n";
      $res_success = $ssh->write($cmd);
      if ($res_success) {
        $res = '';
        $res = $ssh->read();
      }
      if (preg_match('/dhcp/', $res)) {
        $dhcp = 'true';
      } elseif (preg_match('/static/', $res)) { 
        $dhcp = 'false';
      }
      if (isset($dhcp)) $new_info_obj->DHCP__c = $dhcp;
    }
    if (isset($new_info_obj->DHCP__c) AND ($new_info_obj->DHCP__c !== 'true')) {
      $mac_success = False;
      $cmd_arr = ["nvram get wan0_gw_mac; nvram get 1:macaddr\r\n"];
      foreach ($cmd_arr as $cmd) {
        $mac = [0 => ''];
        $rtr_mac = '';
        $res_success = $ssh->write($cmd);
        $res = '';
        if ($res_success) {
          $res = $ssh->read();
        }
        if (preg_match('/([A-F0-9]{2}[:-]){5}[A-F0-9]{2}/i', $res, $mac)) {
          $rtr_mac = strtoupper(str_replace($mac_repl_arr,':',trim($mac[0])));
          $new_info_obj->MAC_Address__c = ($rtr_mac);
          $new_info_obj->MAC_Last_Updated__c = "$today by sflr-01 through API";
          $new_info_obj->MAC_Last_Update = $today;
          $mac_success = True;
        }
      }
    }
    if (isset($new_info_obj->MAC_Address__c) OR isset($new_info_obj->DHCP__c)) {
      $info_arr[$sf_id] = clone $new_info_obj;
      unset($info_arr[$sf_id]->MAC_Last_Updated__c);
      unset($new_info_obj->MAC_Last_Update);
      $sf_update_arr[$sf_id] = $new_info_obj;
      $ct++;
      //if ($ct > 10) break;
    }

    unset($opts, $context, $socket);
    if (!$mac_success) {
      $new_info_obj = new stdClass();
      $new_info_obj->Id = $sf_id;
      $msg = "Automated attempt failed on: $today\nPlease verify $ip_string is correct and SSH is enabled.";
      $new_info_obj->MAC_Last_Updated__c = $msg;
    }
  } // end foreach loop
                                                                                        heavylog("sf_update_arr:\n");
                                                                                        heavylog($sf_update_arr);
  file_put_contents('mac_and_dhcp_info.json', json_encode($info_arr));

                                                                                        heavylog("DONE WITH MAIN LOOP");
} catch (Exception $e) {
  $msg = "Caught exception: $e->getMessage()";
//  $sf_update_arr[1] = new stdClass();
//  $sf_update_arr[1]->error_msg = "ERROR: $msg";
                                                                                        writelog("\n$msg\n");
                                                                                        slack("$rel_path :: $msg" , 'mattd');
}

$json = json_encode($sf_update_arr);
echo $json;



try {
                                                                                        heavylog("\nCREATING NEW SALESFORCE CONNECTION");
  $mySforceConnection = new SforceEnterpriseClient();
  $mySoapClient = $mySforceConnection->createConnection(WSDL);
  $mySession = $mySforceConnection->login(SF_USER,SF_PW);

                                                                                        heavylog("\nCHECKING FOR VALUES TO UPDATE IN AP HEALTH");
  if (count($sf_update_arr) > 0) {
                                                                                        heavylog("\nTHERE ARE VALUES TO UPDATE");
                                                                                        heavylog("\nsf_update_arr:");
                                                                                        heavylog($sf_update_arr);
                                                                                        heavylog("BREAKING ARRAY INTO BITE-SIZED CHUNKS EASY FOR SF TO SWALLOW");
    $chunked_sf_update_arr = array_chunk($sf_update_arr, 200);
                                                                                        heavylog("\nUPDATING MAC ADDR INFO");
    $res_arr = [];
    foreach ($chunked_sf_update_arr as $chunk) {
      $res = $mySforceConnection->update($chunk, 'Client_IP_Detail__c');
      array_merge($res_arr, $res);
    }
    foreach ($res_arr as $res) {
      if( !(isset($res['success']) and isset($res['success']) and $res['success'] === l) ) {
                                                                                        writelog("res:");
                                                                                        writelog($res);
      }
    }
  }
                                                                                        heavylog("\nDONE UPDATING SF");
} catch (Exception $e) {
                                                                                        heavylog("\nCATCH EXCEPTION");
  $msg = "Error creating/updating SF Object(s): $e->faultstring";
                                                                                        writelog("\n$msg");
                                                                                        slack("$rel_path - $msg",'mattd');
}
                                                                                        






$logs_dir = __DIR__ . '/log/';
deleteOldLogs($logs_dir, 60);
                                                                        log_time();
                                                    /////////////////////////////// END EXECUTION CODE ////////////////////////////////////////////





