<?php
/////////////////////////////////////////// Includes //////////////////////////////////////////////
require (__DIR__ . '/../commonDirLocation.php');
//require_once (__DIR__ . '/../autoload.php');
$loader = new \Composer\Autoload\ClassLoader();
$loader->addPsr4('phpseclib\\', realpath(COMMON_PHP_DIR . '/vendor/phpseclib/phpseclib/phpseclib'));
$loader->register();

use phpseclib\Crypt\RSA;
use phpseclib\Net\SSH2;
require_once (COMMON_PHP_DIR . '/vendor/autoload.php');
//require_once (COMMON_PHP_DIR . '/get_last_hop.php');
require_once (COMMON_PHP_DIR . '/SlackMessagePost.php');
require_once (COMMON_PHP_DIR . '/creds.php');
require_once (COMMON_PHP_DIR . '/checkOrgID.php');
require_once (COMMON_PHP_DIR . '/respond.php');
require_once (COMMON_PHP_DIR . '/parseNotification.php');
require_once (COMMON_PHP_DIR . '/deleteOldLogs.php');
require_once (COMMON_PHP_DIR . '/checkWait.php');
require_once (COMMON_PHP_DIR . '/writelog.php');
require_once (COMMON_PHP_DIR . '/logTime.php');
//$wsdl = __DIR__ . '/wsdl/' . 'soapxml.wsdl'; // the wsdl directory location, with file called soapxml.wsdl

//////////////////////////////////////// Variables /////////////////////////////////////////////////
date_default_timezone_set('America/Los_Angeles');
ini_set("soap.wsdl_cache_enabled", "0");  // clean WSDL for develop
$f_name = pathinfo(__FILE__)['basename'];
$f_dir = pathinfo(__FILE__)['dirname'];
$rel_path = substr(__FILE__, strlen($_SERVER['DOCUMENT_ROOT']));
$log_dir = '/log/';
$sf_url = 'https://na131.salesforce.com';
$heavy_logging = 1;



//Test Array:
$request_array = array(
  'OrganizationId' => '000lkjhlkajshldkfalgiu',
  'SessionId' => '000lkjhhskdghfjkdgfkjs',
  'MapsRecords' => array(
    0 => array(
        'Id' => '0060B00000i2v2p',
        'Name' => 'A-S01040799',
        'IP__c' => '162.251.201.218',
    ),
    1 => array(
        'Id' => '0064O00000kbHYS',
        'Name' => 'A-S01040799',
        'IP__c' => '162.251.201.216',
    ),
  ),
  'sObject' => '0'
);




//=================================================== START EXECUTION CODE =========================================================
ob_start(); // start output buffer

writelog("\n\n=====================================================================================================\n\n");
                                                                        log_time();

$config_route_prompt = 'admin@RT.*:';
if (!$request_array) {
/* ///////  if data in request is XML, use this ////////
  $req = file_get_contents('php://input');
  if (empty($req)) {
    $msg = "Request is empty. Responding true and exiting...";
                                                                          heavylog("\n\n$msg");
    //slack("$rel_path :: $msg" , 'mattd');
    respond('true');
    exit;
  }
                                                                          heavylog("\n\nREQ:\n\n");
                                                                          heavylog($req);
  $xml = new DOMDocument();
  $xml->loadXML($req);
  $request_array = parseNotification($xml);
*/
/////////  if data in request is JSON, use this ///////
  $json = file_get_contents('php://input');
  $request_obj = json_decode($json);
  $request_array = (array) $request_obj;
//unset($request_array['sObject']);
}

writelog("\nrequest_array:\n\n");
writelog($request_array);

if (array_key_exists('OrganizationId', $request_array)) {
  $org_id = $request_array['OrganizationId'];
  if (!checkOrgID($org_id)) {
    $msg = "ID check failed.";
    slack($msg, 'mattd');
    writelog ("\n$msg");
    respond('true');
    exit;
  }
} else {
  $msg = "No Org ID found.";
  slack($msg, 'mattd');
  writelog ("\n$msg");
  respond('true');
  exit;
}
                                                                        heavylog("\nREQUEST_ARRAY:\n");                                                                        //writelog($request_array);
$arr_size=count($request_array['MapsRecords']);
if (($arr_size == 1) and (empty($request_array['MapsRecords'][0]))) {
  $msg = "$rel_path: Request is empty.";
                                                                        slack("$rel_path :: $msg", 'mattd');
                                                                        writelog ("\n$msg");
  respond('true');
  exit;
}

$success_count = 0;
writelog("\n NUMBER OF NOTIFICATIONS IN MESSAGE: $arr_size\n");

$msg_array = [];

$sf_response = [];
for($i=0;$i<$arr_size;$i++) {
  $session_id = $request_array['SessionId'];
                                                                        heavylog("\nsession_id: $session_id"); //  value here is 'true' or 'false'
  $sf_id = $request_array['MapsRecords'][$i]['Id'];
  $ip_string = $request_array['MapsRecords'][$i]['IP__c'];
                                                                        heavylog("\nip_string: $ip_string");
  $ip_is_valid = filter_var($ip_string, FILTER_VALIDATE_IP);
  if (!$ip_is_valid) {
    $msg = "IP address: $ip_string is not recognized as valid";
                                                                        writelog("\n\n$msg\n");
    $sf_resposne[$sf_id]->error_msg = "$msg";
  } else {
    $msg_array[$sf_id] = $ip_string;
  }
}

                                                                        heavylog("\n\nMSG_ARRAY:\n");
                                                                        heavylog($msg_array);



$mac_table_obj = json_decode(file_get_contents('mac_table.json'));
print_r("\nmac_table_obj: ");
print_r($mac_table_obj);
ob_flush();
$mac_table_arr = (array) $mac_table_obj;
print_r($mac_table_arr);
ob_flush();


try {
  foreach ($msg_array as $sf_id => $ip_string) {
    print_r("\nip_string: $ip_string");
    $sf_response[$sf_id] = new stdClass();
    $sf_response[$sf_id]->ip_string = $ip_string;

    $already_done = true;
    if ((isset($mac_table_arr[$sf_id]->ip_string)) and
    ($mac_table_arr[$sf_id]->ip_string == $ip_string)) {
      if (isset($mac_table_arr[$sf_id]->mac) and
      preg_match('/([A-F0-9]{2}[:-]){5}[A-F0-9]{2}/i', $mac_table_arr[$sf_id]->mac)) {
        $sf_response[$sf_id]->mac = $mac_table_arr[$sf_id]->mac;
      } else {
        $already_done = false;
      }
      if (isset($mac_table_arr[$sf_id]->dhcp)) {
        $sf_response[$sf_id]->dhcp = $mac_table_arr[$sf_id]->dhcp;
      } else {
        $already_done = false;
      }
    } else {
      $already_done = false;
    }
    if ($already_done) {
      $success_count++;
      continue;
    } else {
      $mac_table_arr[$sf_id] = new stdClass();
      $mac_table_arr[$sf_id]->ip_string = $ip_string;
    }


    // http://us3.php.net/manual/en/context.socket.php
    $opts = array(
      'socket' => array(
        'bindto' => '192.168.2.41:0',
      ),
    );
    $context = stream_context_create($opts);
    $socket = stream_socket_client('tcp://' .$ip_string. ':22', $errno, $errstr, ini_get('default_socket_timeout'), STREAM_CLIENT_CONNECT, $context);
    $ssh = new SSH2($socket);
    $ssh->setTimeout(5);
    if (!$ssh->login('admin', 'ubi@Managed1!!')) {
                                                                        print_r("\nLogin Failed");
    } else {
      $ssh->write("\r"); // somehow works around an issue of premature end of connection on cisco IOS
      if ($ssh->read($config_route_prompt)) {
        $res_success = $ssh->write("nvram get wan0_proto\r\n");
        if ($res_success) {
          $res = $ssh->read();
        }
        if (preg_match('/dhcp/', $res)) {
          $sf_response[$sf_id]->dhcp = ('true');
        } else {
          $sf_response[$sf_id]->dhcp = ('false');
        }
        $mac_table_arr[$sf_id]->dhcp = $sf_response[$sf_id]->dhcp;
      }
      //if ($ssh->read($config_route_prompt)) {
        $res_success = $ssh->write("nvram get wan0_gw_mac\r");
        print_r("\nres_success: $res_success");
        ob_flush();
        if ($res_success) $res = $ssh->read();
        if (preg_match('/([A-F0-9]{2}[:-]){5}[A-F0-9]{2}/i', $res, $mac)) {
          $sf_response[$sf_id]->mac = ($mac[0]);
          $mac_table_arr[$sf_id]->mac = ($mac[0]);
        } else {
          $res_success = $ssh->write("nvram get 1:macaddr\r");
          if ($res_success) $res = $ssh->read();
          if (preg_match('/([A-F0-9]{2}[:-]){5}[A-F0-9]{2}/i', $res, $mac)) {
            $sf_response[$sf_id]->mac = ($mac[0]);
            $mac_table_arr[$sf_id]->mac = ($mac[0]);
          }
        }
      //}
      $success_count++;
      unset($opts, $context, $socket);
    }
  }
  file_put_contents('mac_table.json', json_encode($mac_table_arr));

  if ($success_count == $arr_size) {
    //respond('true');  //// used for outbound message response
  } else {
    $sf_response[$sf_id] = new stdClass();
    $sf_response[$sf_id]->error_msg = "ERROR: Failed to verify MAC address of ASUS managed router with IP: $ip_string\nPlease verify that its IP is correct and SSH is enabled on its WAN interface.";
  }
} catch (Exception $e) {
  $msg = "Caught exception: $e->getMessage()";
  $sf_response[$sf_id] = new stdClass();
  $sf_response[$sf_id]->error_msg = "ERROR: $msg";
                                                                        writelog("\n$msg\n");
                                                                        slack("$rel_path :: $msg" , 'mattd');
}

$resp = ob_get_clean();
$json = json_encode($sf_response);
echo $json;

$logs_dir = __DIR__ . '/log/';
deleteOldLogs($logs_dir, 60);
                                                                        log_time();
                                                    /////////////////////////////// END EXECUTION CODE ////////////////////////////////////////////





