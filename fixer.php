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

/////////////////////////////////////// Functions /////////////////////////////////////////////////




function try_cisco($ip_string) {
                                                                                        heavylog("$ip_string: TRYING CISCO");
  global $mac_success;
  global $today;
  $cisco_rtr_ip = get_last_hop($ip_string);
  print_r("\ncisco_rtr_ip: $cisco_rtr_ip");
  $cisco_ssh = new SSH2($cisco_rtr_ip, 22);
  $cisco_ssh->setTimeout(4);
  if (!$cisco_ssh->login(RTR_U_1, RTR_P_1)) {
    $msg = "$ip_string - Login to Cisco router Failed - IP: $cisco_rtr_ip";
    print_r("\n$msg");
                                                                                                            writelog($msg);
    return False;
  }
  $cmd_arr = ["show arp | incl $ip_string\r"];

  foreach ($cmd_arr as $cmd) {
    $cisco_ssh->write("\r");
    $cisco_ssh->read("#");
    $mac = [0 => ''];
    $rtr_mac = '';
    $res_success = $cisco_ssh->write($cmd);
    $res = '';
    if ($res_success) $res = $cisco_ssh->read();
    if (preg_match('/(0000\.|ffff\.){2}(0|f){4}/', $res)) return False;
    if (preg_match('/([a-f0-9]{4}\.){2}[a-f0-9]{4}/i', $res, $mac)) {
      print_r("\nmac0: $mac[0]");
      $rtr_mac = implode(':',str_split(strtoupper(str_replace('.','',trim($mac[0]))),2));
      print_r("\nrtr_mac from arp: $rtr_mac");
      $new_info_obj = new stdClass();
      $new_info_obj->MAC_Address__c = $rtr_mac;
      $new_info_obj->MAC_Last_Updated__c = "$today by sflr-01 through API";
      $new_info_obj->MAC_Last_Update = $today;
      $mac_success = True;
      return $new_info_obj;
    } else {
      return False;
    }
  }
}





//=================================================== START EXECUTION CODE =========================================================


/*
$file = fopen("ips.txt","r");

while(!feof($file)) {
  $ip = trim(fgets($file));
  if (!empty($ip)) $ip_arr[] = $ip;
}
print_r($ip_arr);
fclose($file);
writelog("\n\n=====================================================================================================\n\n");
log_time();
 
$mySforceConnection = new SforceEnterpriseClient();
$mySoapClient = $mySforceConnection->createConnection($wsdl);
$mylogin = $mySforceConnection->login($USERNAME, $PASSWORD);
$fixer_arr = [];
foreach ($ip_arr as $ip) {
  try {
                                                                                          heavylog("QUERYING SALESFORCE FOR INFO");
  
    $query = "SELECT
      Id
      , IP__c
      , DHCP__c
      , MAC_Address__c
      , Opportunity__c
        FROM Client_IP_Detail__c
        WHERE
        IP__c = '" . $ip . "'";
  
  
    $options = new QueryOptions(2000);  //Set query to return results in chunks
    $mySforceConnection->setQueryOptions($options);
    $done = false;
    $response = $mySforceConnection->query(($query));
    print_r($response);
    echo "Size of records:  " . $response->size."\n";
    $record_arr=array();
    if ($response->size > 0) {
      while (!$done) {
        foreach ($response->records as $record) {
  //                                                                                            print_r($record);
          if (!(empty($record->Opportunity__c))) {
            $sf_id = $record->Id;
            if (!filter_var($record->IP__c, FILTER_VALIDATE_IP)) {
              $msg = $record->IP__c . " is not valid.";
                                                                                              print_r("\n$msg");
              continue;
            }
            $mac_repl_arr = ['-','.',' '];
            //$record->MAC_Address__c = (!empty($record->MAC_Address__c))? strtoupper(str_replace($mac_repl_arr,':',trim($record->MAC_Address__c))) : NULL;
            $record_arr[$sf_id] = $record;
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
                                                                                          writelog("\n$msg\n");
                                                                                          slack("$rel_path :: $msg" , 'mattd');
  }
  
                                                                                          heavylog("DONE QUERYING SALESFORCE");
//  print_r($record_arr);
                                                                                          heavylog("\nSalesforce record count: " . count($record_arr) . "\n\n");
  
  foreach ($record_arr as $sf_id => $obj) $fixer_arr[$sf_id] = $obj;
//  print_r($fixer_arr);
//  break;
}

file_put_contents('fixer_arr.json', json_encode($fixer_arr));

*/

$fixer_arr_json_obj = json_decode(file_get_contents('fixer_arr.json'));





$fixer_arr = ((array) $fixer_arr_json_obj);
$sf_update_arr = [];
foreach($fixer_arr as $sf_id => $obj) {
  $sf_update_obj = new stdClass();
  $sf_update_obj->Id = $sf_id;
  $sf_update_obj->DHCP__c = 'false';
  $sf_update_arr[$sf_id] = $sf_update_obj;
}


try {
                                                                                        heavylog("\nCREATING NEW SALESFORCE CONNECTION");
  $mySforceConnection = new SforceEnterpriseClient();
  $mySoapClient = $mySforceConnection->createConnection(WSDL);
  $mySession = $mySforceConnection->login(SF_USER,SF_PW);
                                                                                        heavylog("\nCHECKING FOR VALUES TO UPDATE IN SF");
  if (count($sf_update_arr) > 0) {
                                                                                        heavylog("\nTHERE ARE VALUES TO UPDATE");
                                                                                        heavylog("\nsf_update_arr:");
                                                                                        heavylog($sf_update_arr);
                                                                                        heavylog("BREAKING ARRAY INTO BITE-SIZED CHUNKS FOR SF");
    $chunked_sf_update_arr = array_chunk($sf_update_arr, 20);
                                                                                        heavylog("\nUPDATING MAC ADDR INFO");
    $res_arr = [];
    foreach ($chunked_sf_update_arr as $chunk) {
      print_r($chunk);
      print_r("\n^chunk^\n");
      $res = $mySforceConnection->update($chunk, 'Client_IP_Detail__c');
      array_merge($res_arr, $res);
      print_r($res);
      sleep(300); 
      foreach($chunk as $obj) {
        $obj->DHCP__c = 'true';
      }
      print_r($chunk);
      print_r("\n^chunk^\n");
      $res = $mySforceConnection->update($chunk, 'Client_IP_Detail__c');
      array_merge($res_arr, $res);
      print_r($res);
      sleep(300);
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






exit;


///////////////////////  Check for duplicate Opportunity IDs (which means there are multiple IPs on the same Opp) and remove them

//////////////// create (parent) Opportunity index
$opp_index = [];
foreach ($record_arr as $sf_id => $obj) $opp_index[$sf_id] = $obj->Opportunity__c;

//////////////// search in Opportunity index for dupes and put them in dupe_arr then remove the dupes from deduped_ip_record_arr
foreach ($record_arr as $sf_id => $obj) $deduped_ip_record_arr[$sf_id] = clone $obj;
$deduped_ip_record_arr_ct = count($deduped_ip_record_arr);
print_r("\n\ndeduped_ip_record_arr_ct: $deduped_ip_record_arr_ct");
$dupe_arr = [];
if (count($record_arr) > 1) {
  foreach ($record_arr as $sf_id => $sf_obj) {
    $dupe_temp_arr = [];
    while ($dupe_sf_id = array_search($sf_obj->Opportunity__c, $opp_index)) {
      unset($opp_index[$dupe_sf_id]);
      $dupe_temp_arr[$dupe_sf_id] = $record_arr[$dupe_sf_id]->Opportunity__c;
    }
    if (count($dupe_temp_arr) > 1) {
      foreach ($dupe_temp_arr as $dupe_sf_id => $parent_opp_id) {
        //print_r("\n$sf_id -- $dupe");
        $dupe_arr[$dupe_sf_id] = $parent_opp_id;
        unset($deduped_ip_record_arr[$sf_id]);
      }
    }
  }
}

print_r("\ndupe_arr:\n");
print_r($dupe_arr);
print_r("\n^dupe_arr^\n");

$deduped_ip_record_arr_ct = count($deduped_ip_record_arr);
print_r("    After removing multiple IPs: $deduped_ip_record_arr_ct\n");






$success_count = 0;

                                                                                        heavylog("LOADING DATA FROM JSON FILE");
$json_obj = json_decode(file_get_contents('mac_and_dhcp_info.json'));
//print_r("\njson_obj: ");
//print_r($json_obj);
$info_arr = (array) $json_obj;
foreach ($info_arr as $sf_id => $obj) {
}


                                                                                        heavylog("PARSING JSON AND DETERMINING WHICH ROUTERS TO ATTEMPT TO UPDATE");
try {

  if (!empty($argv[1])) {
    foreach ($record_arr as $sf_id => $record_obj) {
      $sf_update_obj = new stdClass();
      $sf_update_obj->IP__c = $record_obj->IP__c;
      $to_update_arr[$sf_id] = $sf_update_obj;
    }
  } else {
    
    foreach ($record_arr as $sf_id => $record_obj) {
      $need_to_update_sf = False;
      if (isset($info_arr[$sf_id])) {
        $info_obj = $info_arr[$sf_id];
        if (isset($info_obj->MAC_failed_attempts)) {
          if (($info_obj->MAC_failed_attempts > 3) AND ($info_obj->MAC_failed_attempts <= 20)) {
            $info_obj->MAC_failed_attempts++;
            continue;
          }
          if ($info_obj->MAC_failed_attempts > 20) $info_obj->MAC_failed_attempts = 0;
        } else {
          $info_obj->MAC_failed_attempts = 1;
        }
        if (isset($info_obj->MAC_Last_Update) AND ((strtotime("now") - strtotime($info_obj->MAC_Last_Update)) < (0 * 24 * 60 * 60 ))) continue;
        if (isset($info_obj->MAC_Address__c)) {
          if ((isset($record_obj->MAC_Address__c) AND preg_match('/([A-F0-9]{2}:){5}[A-F0-9]{2}/i', $record_obj->MAC_Address__c) AND
             ($record_obj->MAC_Address__c !== $info_obj->MAC_Address__c)) OR
             !isset($info_obj->MAC_Last_Update) OR 
             (strtotime("now") - strtotime($info_obj->MAC_Last_Update)) > (7 * 24 * 60 * 60 ) OR
             !isset($record_obj->MAC_Address__c)) {
            $need_to_update_sf = True;
          }
          //if ($record_obj->DHCP__c !== 'true') {
          //  $need_to_update_sf = True;
          //}
          if ($record_obj->MAC_Address__c == '00:00:00:00:00:00') {
            $need_to_update_sf = True;
          }
        } else {
          $need_to_update_sf = True;
        }
      } else {
        $need_to_update_sf = True;
      }
      if ($need_to_update_sf) {
        $sf_update_obj = new stdClass();
        //$sf_update_obj->Id = $sf_id;
        $sf_update_obj->IP__c = $record_obj->IP__c;
        $to_update_arr[$sf_id] = $sf_update_obj;
      }  
    }
  }
                                                                                        //heavylog($to_update_arr);
  $count = count($to_update_arr);
                                                                                        heavylog("COUNT TO UPDATE: $count");
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
    $mac_success = False;
    $login_success = False;
    $tried_cisco = False;
    $ip_string = $sf_obj->IP__c;
    print_r("\n$ip_string");
    
    $secure1 = check_for_peer_name_in_ssl_cert($ip_string . ':8443', 'router.asus.com');
    $secure2 = check_for_peer_name_in_ssl_cert($ip_string . ':8443', '192.168.50.1');
    ob_end_flush(); 
    if (!($secure1 OR $secure2)) {
      $msg = " seems insecure or could not be contacted.";
      print_r("$msg");
      $new_info_obj = try_cisco($ip_string);
      //$new_info_obj->Id = $sf_id;

      $tried_cisco = True;
    }
    unset($secure1, $secure2);

    $ssh = new SSH2($ip_string, 22);
    $ssh->setTimeout(2);
    if (!$ssh->login(ASUS_USER, ASUS_PASS)) {
      $msg = "$ip_string - Login Failed";
                                                                                        heavylog($msg);
    } else {
      $login_success = True;
    }
    $ssh->write("\r"); // somehow works around an issue of premature end of connection on cisco IOS

    if ($login_success AND $ssh->read($config_route_prompt)) {
      $new_info_obj = new stdClass();
      //$new_info_obj->Id = $sf_id;
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
      //if (isset($dhcp)) $new_info_obj->DHCP__c = $dhcp;
    }
    //if (isset($new_info_obj->DHCP__c) AND ($new_info_obj->DHCP__c !== 'true')) {
      $cmd_arr = ["nvram get 0:macaddr; nvram get et0macaddr\r\n"];
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
          print_r("\nrtr_mac from device: $rtr_mac");
          $new_info_obj->MAC_Address__c = $rtr_mac;
          $new_info_obj->MAC_Last_Updated__c = "$today by sflr-01 through API";
          $new_info_obj->MAC_Last_Update = $today;
          $mac_success = True;
        }
      }
    //}
    if (!$mac_success AND !$tried_cisco) {
      $new_info_obj = try_cisco($ip_string);
      //$new_info_obj->Id = $sf_id;
    }
print_r("\ndupe_arr:\n");
print_r($dupe_arr);
    if ($mac_success AND !isset($dupe_arr[$sf_id])) $new_info_obj->DHCP__c = 1;

    if (isset($new_info_obj->MAC_Address__c)) {
      $sf_update = false;
      $info_arr[$sf_id] = clone $new_info_obj;
      unset($info_arr[$sf_id]->MAC_Last_Updated__c);
      unset($new_info_obj->MAC_Last_Update);
      $sf_source_obj = $record_arr[$sf_id];
      $sf_update_obj = new stdClass();
      $sf_update_obj->Id = $sf_id;
print_r("\nsf_source_obj:\n");
print_r($sf_source_obj);
print_r("\nnew_info_obj:\n");
print_r($new_info_obj);
      foreach ((array) $new_info_obj as $new_info_prop_name => $new_info_prop_val) {
        if ($new_info_prop_val !== $sf_source_obj->$new_info_prop_name) {
          $sf_update = True;
          $sf_update_obj->$new_info_prop_name = $new_info_prop_val;
        }
      } 
print_r("\nsf_update_obj:\n");
print_r($sf_update_obj);
      if (!$sf_update) {
      echo"   NOT SENT";
        unset ($sf_update_obj);
      } else { 
        $sf_update_arr[$sf_id] = $sf_update_obj;
      echo"   SENT";
        $ct++;
      }

      print "\nSF update count: $ct";
      if ($ct == 50) break;
    }

    if (!$mac_success) {
      if (isset($info_arr[$sf_id]->MAC_failed_attempts)) {
        $info_arr[$sf_id]->MAC_failed_attempts++;
      } else {
        $info_arr[$sf_id]->MAC_failed_attempts = 1;
      }
      $new_info_obj = new stdClass();
      $new_info_obj->Id = $sf_id;
      $msg = "Automated attempt failed on: $today\nPlease verify $ip_string is correct and SSH is enabled.";
      $new_info_obj->MAC_Last_Updated__c = $msg;
    }
  } // end foreach loop



  $count = count($sf_update_arr);
                                                                                        heavylog("COUNT OF RECORDS TO UPDATE IN SF: $count");
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





