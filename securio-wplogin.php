<?php
/* 
Plugin Name: Securio WpLogin (beta)
Plugin URI: http://www.secur.io/
Version: v0.9
Author: Noah Spirakus
Description: Securio WP-Login allows you to secure the wordpress login by tracking brute force attempts and by allowing the enabling of Multi-Factor Authentication using Securio's enterprise platform or any TOTP capable device like Google Authenticator
*/

/*
== Change Log ==

	ver. 1.0 Jan-17-2012
	- released
*/

/*
== Installation ==

1. Extract the zip file into your plugins directory into its own folder.
2. Activate the plugin in the Plugin options.
3. Customize the settings from the Settings => Securio WPLogin panel, if desired.

*/

/*
== SPECIAL THANKS ==

Thanks to Michael VanDeMar for his original Login Lockdown plugin
	http://www.bad-neighborhood.com/
Thanks to Henrik Schack for his Google Authenticator plugin
	http://henrik.schack.dk/
Thanks to Bryan Ruiz for his Base32 encode/decode class, found at php.net.
Thanks to Tobias Bäthge for his major code rewrite to Google Authenticator plugin
Thanks to Daniel Werl for his usability tips integrated in Google Authenticator plugin.
Thanks to Dion Hulse for his bugfixes to Google Authenticator.

*/

/*
== Licensing ==

Securio WpLogin - Secure your login using Multi-Factor and mitigate bruteforce login attempts.
Copyright (C) 2012 - 2013, Noah Spirakus, http://www.secur.io || http://www.noahjs.com
All rights reserved.

License: GPL

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

*/







/**
 * Startup all classes
 */
$Securio_BruteForce = new Securio_BruteForce();		// Brute Force Protection
$Securio_MFA 		= new Securio_MFA();			// Multi-Factor
$Securio_WPLogin 	= new Securio_WPLogin();		// Parent





/**
 * Used by all classes to GET Securio WPLogin Options
 */
function securio_get_options() {
	
	// Set Defaults
	$Securio_WPLoginOptions = array(
			'MFA_enabled' 			=> 1,
			'BF_enabled' 			=> 1,
			'max_login_retries' 	=> 3,
			'retries_within' 		=> 5,
			'lockout_length' 		=> 60,
			'ban_invalid_usernames' => 'enabled',
			'mask_login_errors' 	=> 'enabled',
			'trust_proxy' 			=> 0,
			'trusted_proxy_header' 	=> 'PROXY_REMOTE_ADDR',
			'trusted_proxy_ips' 	=> '',
		);

	// Get Options
	$db_options = get_option("securio_WPLoginOptions");
	if ( !empty($db_options) ) {
		foreach ( $db_options as $key => $option ) {
			$Securio_WPLoginOptions[$key] = $option;
		}
	}else{
		// Save them to DB
		update_option("securio_WPLoginOptions", $Securio_WPLoginOptions);
	}

	return $Securio_WPLoginOptions;
	
}



/************************************
 ** 	  Primary Plugin Class     **
 ************************************/
class Securio_WPLogin{


	static $instance;


	function __construct() {
	    
		global $wpdb, $Securio_BruteForce, $Securio_MFA;

	    self::$instance = $this;

		$this->wpdb = $wpdb;
	    $this->db_version = "1.0";

		// Table Names
		define('SECURIO_TABLE_AUTHS', $this->wpdb->prefix . "securio_bf_fails");
		define('SECURIO_TABLE_BANS', $this->wpdb->prefix . "securio_bf_bans");


	    // Load Options
		$this->options = securio_get_options();

		
		// Init Logins
		    if( $Securio_BruteForce ){
		    	$Securio_BruteForce->init_login();
		    }
		    if( $Securio_MFA ){
		    	$Securio_MFA->init_login();
			}
	    

	    // Add login Action
		add_action( 'login_form', 	array( $this, 		 'securio_credit_link'));
		add_action('admin_menu', array( $this, 'securio_wplogin_ap'));

		register_activation_hook (__FILE__, array($this, "activation") );
		register_deactivation_hook (__FILE__, array($this, "deactivation") );
		

		// Occasioanlly cleanup
		$last_clean = get_option('SecurioWPLoginCleanupDate');
		if( !$last_clean OR $last_clean <  (time() - 86400*3) ){	// Every 3 Days run cleanup
			$this->cleanup();
		}


	}


	/**
	 * Primary Cleanup for WPLogin, calls BruteForce Cleanup
	 */
	function cleanup(){


		if( $this->options['BF_enabled'] ){

			// Clean old BANs
			$insert = "DELETE FROM " . SECURIO_TABLE_BANS . " WHERE date_added < ".(time() - 86400*14)."";	// 14 days of logs
			$results = $this->wpdb->query($insert);

			// Clean old Auths
			$insert = "DELETE FROM " . SECURIO_TABLE_AUTHS . " WHERE date_added < ".(time() - 86400*14)."";	// 14 days of logs
			$results = $this->wpdb->query($insert);
			
		}

		update_option( "Securio_WPLoginCleanupDate", time() );

	}



	/**
	 * Note the Login Form is protected by Securio
	 */
	function securio_credit_link(){
		echo "<p>Login protected by <a href='https://www.secur.io/'>Securio WPLogin</a>.<br /><br /><br /></p>";
	}





	/**
	 * activation
	 */
	function activation() {

		// Load to handle DB Upgrades
		//require_once(ABSPATH . 'wp-admin/upgrade.php');

		if( $this->wpdb->get_var("SHOW TABLES LIKE '".SECURIO_TABLE_AUTHS."'") != SECURIO_TABLE_AUTHS ) {
			
			$sql = "CREATE TABLE " . SECURIO_TABLE_AUTHS . " (
				`id` bigint(20) NOT NULL AUTO_INCREMENT,
				`user_name` bigint(20) NOT NULL,
				`user_id` bigint(20) NOT NULL,
				`user_ip` varchar(100) NOT NULL default '',
				`user_proxyip` varchar(100) default '',
				`date_added` bigint(12) NOT NULL default '0',
				PRIMARY KEY  (`id`)
			   );";
			
			 $this->wpdb->query($sql);
		}

		if( $this->wpdb->get_var("SHOW TABLES LIKE '".SECURIO_TABLE_BANS."'") != SECURIO_TABLE_BANS ) {
			
			$sql = "CREATE TABLE " . SECURIO_TABLE_BANS . " (
				`id` bigint(20) NOT NULL AUTO_INCREMENT,
				`user_id` bigint(20) NOT NULL,
				`user_ip` varchar(100) NOT NULL default '',
				`user_proxyip` varchar(100) default '',
				`date_added` bigint(12) NOT NULL default '0',
				`date_expires` bigint(12) NOT NULL default '0',
				PRIMARY KEY  (`id`)
			   );";
			
			 $this->wpdb->query($sql);
		}

		add_option("securio_wplogin_db_version", $this->db_version);

		update_option( "Securio_WPLoginCleanupDate", time() );

	}
	/**
	 * deactivation
	 */
	function deactivation() {

		// Load to handle DB Upgrades
		//require_once(ABSPATH . 'wp-admin/upgrade.php');

		// DROP BF Table for Auths
		$sql = "DROP TABLE " . SECURIO_TABLE_AUTHS . ";";
		$this->wpdb->query($sql);
		
		// DROP BF Table for Bans
		$sql = "DROP TABLE " . SECURIO_TABLE_BANS . ";";
		$this->wpdb->query($sql);

		// Remove all User META Information
		$sql = "DELETE FROM ".$this->wpdb->prefix.'usermeta'." WHERE meta_key LIKE 'securio_%';";
		$this->wpdb->query($sql);

		// Remove all WP OPTIONS
		$sql = "DELETE FROM ".$this->wpdb->prefix.'options'." WHERE option_name LIKE 'securio_%';";
		$this->wpdb->query($sql);

	}

	/**
	 * Handle Primary Securio WPLogin Settings in Admin
	 */
	function print_securiowploginAdminPage() {

		global $Securio_BruteForce, $Securio_MFA;
		
		$Securio_WPLoginOptions = securio_get_options();

		if (isset($_POST['update_securiowploginSettings'])) {

			//wp_nonce check
			check_admin_referer('login-ban_update-options');

			if (isset($_POST['MFA_enabled'])) {
				$Securio_WPLoginOptions['MFA_enabled'] 			= ( $_POST['MFA_enabled'] == 'enabled' ) ? 1 : 0;
			}

			if (isset($_POST['BF_enabled'])) {
				$Securio_WPLoginOptions['BF_enabled'] 			= ( $_POST['BF_enabled'] == 'enabled' ) ? 1 : 0;
			}
			if (isset($_POST['BF_max_login_retries'])) {
				$Securio_WPLoginOptions['max_login_retries'] 	= $_POST['BF_max_login_retries'];
			}
			if (isset($_POST['BF_retries_within'])) {
				$Securio_WPLoginOptions['retries_within'] 		= $_POST['BF_retries_within'];
			}
			if (isset($_POST['BF_lockout_length'])) {
				$Securio_WPLoginOptions['lockout_length'] 		= $_POST['BF_lockout_length'];
			}
			if (isset($_POST['BF_ban_invalid_usernames'])) {
				$Securio_WPLoginOptions['ban_invalid_usernames'] = ( $_POST['BF_ban_invalid_usernames'] == 'enabled' ) ? 1 : 0;
			}
			if (isset($_POST['BF_mask_login_errors'])) {
				$Securio_WPLoginOptions['mask_login_errors'] 	= ( $_POST['BF_mask_login_errors'] == 'enabled' ) ? 1 : 0;
			}
			if (isset($_POST['BF_trust_proxy'])) {
				$Securio_WPLoginOptions['trust_proxy'] 			= ( $_POST['BF_trust_proxy'] == 'enabled' ) ? 1 : 0;
			}
			if (isset($_POST['BF_trusted_proxy_ips'])) {
				$Securio_WPLoginOptions['trusted_proxy_ips'] 	= $_POST['BF_trusted_proxy_ips'];
			}
			if (isset($_POST['BF_trusted_proxy_header'])) {
				$Securio_WPLoginOptions['trusted_proxy_header'] = $_POST['BF_trusted_proxy_header'];
			}
			update_option("securio_WPLoginOptions", $Securio_WPLoginOptions);
			
			// Flash Message
			echo '<div class="updated"><p><strong>Settings Updated.</strong></p></div>';
		
		}
		if (isset($_POST['release_securio_auth_bans'])) {

			//wp_nonce check
			check_admin_referer('login-ban_release-securio_auth_bans');

			if (isset($_POST['releaseme'])) {

				// Load DB
				global $wpdb;

				// Run through List
				foreach ( $_POST['releaseme'] as $id ) {
					$Securio_BruteForce->release_ban( $id );
				}

			}
			update_option("securio_WPLoginOptions", $Securio_WPLoginOptions);

			// Flash Message
			echo '<div class="updated"><p><strong>Selected Bans have been Released.</strong></p></div>';
			
		}
		
		$list_of_banned = $Securio_BruteForce->get_list_banned();

		// INCLUDE VIEW
		include('views/admin_settings.php');

	}

	function securio_wplogin_ap() {
		if ( function_exists('add_options_page') ) {
			add_options_page('Securio WPLogin', 'Securio WPLogin', 9, basename(__FILE__), array( $this, 'print_securiowploginAdminPage') );
		}
	}

}


/************************************
 ** 	    Brute Force Class      **
 ************************************/
class Securio_BruteForce {

	static $instance;

	function __construct() {
	    
	    self::$instance = $this;

		global $wpdb;
	    $this->wpdb  =  $wpdb;

		$this->options = securio_get_options();

		// Get us moving
	    add_action( 'init', array( $this, 'init' ) );
	}	

	/**
	 * Initialization of Hooks
	 */
	function init() {

		// Nothing to do

	}

	/**
	 * Initialization of login
	 */
	function init_login() {

		if( $this->options['BF_enabled'] ){
			
			remove_filter('authenticate', array( $this, 'wp_authenticate_username_password'), 20, 3);
			add_filter('authenticate', 	array( $this, 'BF_wp_authenticate_username_password'), 20, 3);
				
		}

	}

	/**
	 * How many failed attmpts has this IP done withing options time period
	 *
	 * 	@return Is Banned?
	 */
	function auth_count_failed() {

		$ip 	 = $this->get_ip();
		$class_c = substr ($ip, 0 , strrpos ( $ip, "." ));

		return $this->wpdb->get_var("SELECT COUNT(id) FROM ".SECURIO_TABLE_AUTHS." WHERE date_added  > " . ( time() - ($this->options['retries_within']*60) ) ." AND user_ip LIKE '" . $this->wpdb->escape($class_c) . "%'");
			
	}


	/**
	 * Log a failed AUthentication
	 * 	@param Username
	 */
	function auth_log_failed($username = "") {

		$ip = $this->get_ip();

		$username = sanitize_user($username);
		$user = get_user_by('login',$username);
		if ( $user || ( $this->options['ban_invalid_usernames'] != "enabled" ) ) {
			$insert = "INSERT INTO " . SECURIO_TABLE_AUTHS . " (user_id, user_name, date_added, user_ip) VALUES ('" . $user->ID . "', '".$this->wpdb->escape($username)."', '".time()."', '" . $this->wpdb->escape($ip) . "')";
			$results = $this->wpdb->query($insert);
		}

	}


	/**
	 * BAN the current IP of the User attempting to Login
	 * 	@param Username <not currently used>
	 */
	function ban_ip($username = "") {
		
		$ip = $this->get_ip();

		$username = sanitize_user($username);
		$user = get_user_by('login',$username);
		if ( $user || ( $this->options['ban_invalid_usernames'] != "enabled" ) ) {

			$date_expires = time()  + $this->options['lockout_length'] * 60;

			$insert = "INSERT INTO " . SECURIO_TABLE_BANS . " (user_id, date_added, date_expires, user_ip) VALUES ('" .(int)$user->ID . "', '".time()."', '".(int)$date_expires."', '" . $this->wpdb->escape($ip) . "')";
			$results = $this->wpdb->query($insert);

		}

	}


	/**
	 * Release BAN on a particular Record (IP)
	 * 	@param Ban ID from DB
	 */
	function release_ban( $id ) {
		
		return $this->wpdb->query("UPDATE ".SECURIO_TABLE_BANS." SET date_expires = '".time()."' WHERE id = " . $this->wpdb->escape($id) );

	}


	/**
	 * Check if current user logging has banned IP
	 *
	 * 	@return Is Banned?
	 */
	function is_banned() {
		
		$ip = $this->get_ip();
		$class_c = substr ($ip, 0 , strrpos ( $ip, "." ));

		$stillLocked = $this->wpdb->get_var("SELECT user_id FROM ".SECURIO_TABLE_BANS." WHERE date_expires > ".time()." AND user_ip LIKE '" . $this->wpdb->escape($class_c) . "%'");
		
		return $stillLocked;
	}


	/**
	 * Return array of currently Banned IPs
	 *
	 * 	@return Array IPs
	 */
	function try_ban( $username ) {
		
		if ( $this->options['max_login_retries'] <= $this->auth_count_failed() ) {
			
			// BAN IP
			$this->ban_ip($username);

			return true;

		}else{
			return false;
		}
	}


	/**
	 * Return array of currently Banned IPs
	 *
	 * 	@return Array IPs
	 */
	function get_list_banned() {
		
		// Return list of banned IP addresses
		return $this->wpdb->get_results("SELECT id, floor((date_expires-".time().")/60) AS minutes_left, user_ip FROM ".SECURIO_TABLE_BANS." WHERE date_expires > '".time()."'", ARRAY_A);

	}


	/**
	 * Process normal portaion of WP Authentication
	 * 	@param user
	 * 	@param username
	 * 	@param password
	 *
	 * 	@return User
	 */
	function BF_wp_authenticate_username_password($user, $username, $password) {
		
		if ( is_a($user, 'WP_User') ) { return $user; }

		if ( empty($username) || empty($password) ) {
			$error = new WP_Error();

			if ( empty($username) ){
				$error->add('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
			}
			if ( empty($password) ){
				$error->add('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
			}
			return $error;
		}

		$userdata = get_user_by('login',$username);

		if ( !$userdata ) {
			return new WP_Error('invalid_username', sprintf(__('<strong>ERROR</strong>: Invalid username. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), site_url('wp-login.php?action=lostpassword', 'login')));
		}

		$userdata = apply_filters('wp_authenticate_user', $userdata, $password);
		if ( is_wp_error($userdata) ) {
			return $userdata;
		}

		if ( !wp_check_password($password, $userdata->user_pass, $userdata->ID) ) {
			return new WP_Error('incorrect_password', sprintf(__('<strong>ERROR</strong>: Incorrect password. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), site_url('wp-login.php?action=lostpassword', 'login')));
		}

		$user =  new WP_User($userdata->ID);
		return $user;
	}


	/**
	 * Process BF portion of WP Authentication
	 * 	@param username
	 * 	@param password
	 *
	 * 	@return User
	 */
	function wp_authenticate($username, $password) {
		
		$username = sanitize_user($username);
		$password = trim($password);

		if ( "" != $this->is_banned() ) {
			return new WP_Error('incorrect_password', "<strong>ERROR</strong>: We're sorry, but this IP range has been blocked due to too many recent failed login attempts.<br /><br />Please try aSMFAin later.");
		}

		$user = apply_filters('authenticate', null, $username, $password);

		if ( $user == null ) {
			// TODO what should the error message be? (Or would these even happen?)
			// Only needed if all authentication handlers fail to return anything.
			$user = new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid username or incorrect password.'));
		}

		$ignore_codes = array('empty_username', 'empty_password');

		if (is_wp_error($user) && !in_array($user->get_error_code(), $ignore_codes) ) {
			
			// Increment Failed
			$this->auth_log_failed($username);
			
			// Failed Possibilities
			if ( $this->try_ban($username) ) {
				// ok we banned
				return new WP_Error('incorrect_password', __("<strong>ERROR</strong>: We're sorry, but this IP range has been blocked due to too many recent failed login attempts.<br /><br />Please try aSMFAin later."));
			}else{
				// Still able to go another round
				if ( $this->options['mask_login_errors'] == 1 ) {
					return new WP_Error('authentication_failed', sprintf(__('<strong>ERROR</strong>: Invalid username or incorrect password. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), site_url('wp-login.php?action=lostpassword', 'login')));
				} else {
					do_action('wp_login_failed', $username);
				}
			}

		}

		return $user;
	}


	/**
	 * GET The IP of user trying to login
	 *
	 * 	@return IP Address
	 */
	function get_ip(){

		if ( $this->options['trust_proxy'] AND ( stripos($this->options['trusted_proxy_ips'], $_SERVER['REMOTE_ADDR'] ) !== false  ) ){	// Trusted proxy IPs saved as " |1.2.3.4|2.3.4.5|3.4.5.6| "

			// Make sure header exists
			if ( isset( $_SERVER[ $this->options['trusted_proxy_header'] ] ) ){
				return $_SERVER[ $this->options['trusted_proxy_header'] ];
			}else{
				return $_SERVER['REMOTE_ADDR'];
			}

		}else{
			return $_SERVER['REMOTE_ADDR'];
		}

	}

}

/************************************
 ** 	   Multi-Factor Class      **
 ************************************/
class Securio_MFA {

	static $instance;

	function __construct() {

	    self::$instance = $this;

		$this->db_version = "1.0";
		$this->options = securio_get_options();

	    //  Startup
	    add_action( 'init', array( $this, 'init' ) );
	}


	/**
	 * Initialization the plugin hooks
	 */
	function init() {


		if( $this->options['MFA_enabled'] ){

			require_once( 'libs/base32.php' );

			if ( defined( 'DOING_AJAX' ) && DOING_AJAX ){
				add_action( 'wp_ajax_securio_mfa_action', array( $this, 'ajax_callback' ) );
			}

			add_action( 'personal_options_update', 	array( $this, 'personal_options_update' ) );
			add_action( 'profile_personal_options', array( $this, 'profile_personal_options' ) );
			add_action( 'edit_user_profile', 		array( $this, 'edit_user_profile' ) );
			add_action( 'edit_user_profile_update', array( $this, 'edit_user_profile_update' ) );

		}
		
	}

	/**
	 * Initialization of login page
	 */
	function init_login() {
		
		if( $this->options['MFA_enabled'] ){

			add_filter( 'authenticate', array( $this, 'check_otp' ), 50, 3 );
			add_action( 'login_form',   array( $this, 'loginform' ) );
			
		}

	}


	/**
	 * Show Form when logedin User is editing Profile
	 */
	function profile_personal_options() {

		global $user_id, $is_profile_page;	// Get User ID being viewed and if it is current logged in User

		// If editing of Securio Multi-Factor settings has been disabled, just return
		$MFA_hidefromuser = trim( get_user_option( 'securio_mfa_hidefromuser', $user_id ) );
		if ( $MFA_hidefromuser == 'enabled') return;
		
		$MFA_secret			= trim( get_user_option( 'securio_mfa_secret', $user_id ) );
		$MFA_enabled		= trim( get_user_option( 'securio_mfa_enabled', $user_id ) );
		$MFA_device			= trim( get_user_option( 'securio_mfa_device', $user_id ) );
		$MFA_relaxedmode	= trim( get_user_option( 'securio_mfa_relaxedmode', $user_id ) );
		$MFA_description	= trim( get_user_option( 'securio_mfa_description', $user_id ) );
		$MFA_pwdenabled		= trim( get_user_option( 'securio_mfa_pwdenabled', $user_id ) );
		$MFA_password		= trim( get_user_option( 'securio_mfa_passwords', $user_id ) );
		
		// We dont store the generated app password in cleartext so there is no point in trying
		// to show the user anything except from the fact that a password exists.
		if ( $MFA_password != '' ) {
			$MFA_password = "XXXX XXXX XXXX XXXX";
		}

		// In case the user has no secret ready (new install), we create one.
		if ( $MFA_secret == '' ) {
			$MFA_secret = $this->create_secret();
		}
		
		// Default Description that shows in App
		if ( $MFA_description == '' ) {

			// Make Domain pretty
			$domain = get_option('siteurl'); //or 
			$domain = str_replace('http://', '', $domain);
			$domain = str_replace('www', '', $domain); 
			
			// Starting Description
			$MFA_description = 'Wordpress - '.$domain;
		}

		$time_count = floor( time() / 30 );
		
		for ($i=-1; $i<=1; $i++) {
			$current_codes[]	=	$this->gen_code($MFA_secret, ($time_count+$i) );
		}
		

		// LOAD VIEW
		include('views/profile_personal.php');	
			
	}


	/**
	 * Process Form Submission from "profile_personal_options"
	 */
	function personal_options_update() {

		global $user_id;	// User ID we are viewing (logged in user)

		// If editing of Securio Multi-Factor settings has been disabled, just return
		$MFA_hidefromuser = trim( get_user_option( 'securio_mfa_hidefromuser', $user_id ) );
		if ( $MFA_hidefromuser == 'enabled'){
			return;
		}


		$MFA_enabled		=	( empty( $_POST['MFA_enabled'] )      ) ? 'disabled' : 'enabled';
		$MFA_relaxedmode	=	( empty( $_POST['MFA_relaxedmode'] ) ) ? 'disabled' : 'enabled';
		$MFA_pwdenabled		=	( empty( $_POST['MFA_pwdenabled'] ) ) ? 'disabled' : 'enabled';

		$MFA_description	= trim( $_POST['MFA_description'] );
		$MFA_device			= trim( $_POST['MFA_device'] );
		$MFA_secret			= trim( $_POST['MFA_secret'] );
		$MFA_password		= str_replace(' ', '', trim( $_POST['MFA_password'] ) );
		
		
		// Only store password if a new one has been generated.
		if (strtoupper($MFA_password) != 'XXXXXXXXXXXXXXXX' ) {
			
			// Store the password in a format that can be expanded easily later on if needed.
			$MFA_password = array( 'appname' => 'Default', 'password' => $this->hash( $MFA_password ) );
			update_user_option( $user_id, 'securio_mfa_passwords', json_encode( $MFA_password ), true );

		}
		
		update_user_option( $user_id, 'securio_mfa_enabled', 	$MFA_enabled, true );
		update_user_option( $user_id, 'securio_mfa_description', $MFA_description, true );
		update_user_option( $user_id, 'securio_mfa_device', 		$MFA_device, true );
		update_user_option( $user_id, 'securio_mfa_relaxedmode', $MFA_relaxedmode, true );
		update_user_option( $user_id, 'securio_mfa_secret', 		$MFA_secret, true );
		update_user_option( $user_id, 'securio_mfa_pwdenabled', 	$MFA_pwdenabled, true );

	}


	/**
	 * Show Form when Admin editing User
	 */
	function edit_user_profile() {

		global $user_id;	// User ID we are viewing

		$MFA_enabled      = trim( get_user_option( 'securio_mfa_enabled', $user_id ) );
		$MFA_hidefromuser = trim( get_user_option( 'securio_mfa_hidefromuser', $user_id ) );
		
		// LOAD VIEW
		include('views/edit_user.php');	

	}


	/**
	 * Process Form Submission from "edit_user_profile"
	 */
	function edit_user_profile_update() {

		global $user_id;	// User ID we are viewing
		
		$MFA_enabled		=	( empty( $_POST['MFA_enabled'] )      ) ? 'disabled' : 'enabled';
		$MFA_hidefromuser	=	( empty( $_POST['MFA_hidefromuser'] ) ) ? 'disabled' : 'enabled';

		update_user_option( $user_id, 'securio_mfa_enabled', $MFA_enabled, true );
		update_user_option( $user_id, 'securio_mfa_hidefromuser', $MFA_hidefromuser, true );

	}


	/**
	 * Show OTP Login Form
	 */
	function loginform() {
		
		include('views/login_mfa.php');

	}



	/**
	 * Not sure we will have BCrypt or others so create long-running version of hash
	 * 	@param data
	 * 	@param rounds to hash
	 *
	 * 	@return hash result
	 */
	function hash( $data, $rounds = 5000 ){

		// Init
		$hash  =  $data;

		// Use incrementer to generate Incrementing Key used to hash Data
		for( $i=0; $i<$rounds; $i++ ){
			$hash  =  hash_hmac('sha256', $hash, md5($i) );
		}

	return $hash;
	}


	/**
	 * Verify the User submitted OTP
	 * 	@param secretkey
	 * 	@param submitted_otp
	 * 	@param relaxedmode
	 *
	 * 	@return Valid OTP?
	 */
	function verify( $secretkey, $submitted_otp, $relaxedmode ) {

		// Did the user enter 6 digits ?
		if ( strlen( $submitted_otp ) != 6) {
			return false;
		} else {
			$submitted_otp = intval ( $submitted_otp );
		}

		// If user is running in relaxed mode, we allow more time drifting
		// ±4 min, as opposed to ± 30 seconds in normal mode.
		if ( $relaxedmode == 'enabled' ) {
			$firstcount = -8;
			$lastcount  =  8; 
		} else {
			$firstcount = -1;
			$lastcount  =  1; 	
		}
		
		$tm = floor( time() / 30 );
		
		$secretkey=Base32::decode($secretkey);
		// Keys from 30 seconds before and after are valid aswell.
		for ($i=$firstcount; $i<=$lastcount; $i++) {
			
			// Gernate Code
			$value 	=	$this->gen_code( $secretkey, $tm+$i );
			if ( $value == $submitted_otp ) {
				return true;
			}

		}
		return false;
	}
	

	/**
	 * Generate OTP Code from SECRET and COUNTER
	 * 	@param secretkey
	 * 	@param counter
	 *
	 * 	@return OTP
	 */
	function gen_code( $secretkey, $counter ) {
		
		$secretkey=Base32::decode($secretkey);
		// Pack time into binary string
		$time=chr(0).chr(0).chr(0).chr(0).pack('N*',$counter);
		// Hash it with users secret key
		$hm = hash_hmac( 'SHA1', $time, $secretkey, true );
		// Use last nipple of result as index/offset
		$offset = ord(substr($hm,-1)) & 0x0F;
		// grab 4 bytes of the result
		$hashpart=substr($hm,$offset,4);
		// Unpak binary value
		$value=unpack("N",$hashpart);
		$value=$value[1];
		// Only 32 bits
		$value = $value & 0x7FFFFFFF;
		$value = $value % 1000000;
		
		return $value;

	}

	// Generate random TOTP/HOTP Secret
	function create_secret() {
	    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // allowed characters in Base32
	    $secret = '';
	    for ( $i = 0; $i < 16; $i++ ) {
	        $secret .= substr( $chars, wp_rand( 0, strlen( $chars ) - 1 ), 1 );
	    }
	    return $secret;
	}



	/**
	 * MFA Login Form Code (only shows if active for User)
	 * 	@param wordpressuser
	 * 	@param username
	 *	@param password
	 *
	 * 	@return user/loginstatus
	 */
	function check_otp( $user, $username = '', $password = '' ) {
		// Store result of loginprocess, so far.
		$userstate = $user;

		// Get information on user, we need this in case an app password has been enabled,
		// since the $user var only contain an error at this point in the login flow.
		$user = get_user_by( 'login', $username );

		// Does the user have the Securio Multi-Factor enabled ?
		if ( $user != null AND trim(get_user_option( 'securio_mfa_enabled', $user->ID ) ) == 'enabled' ) {

			// Get the users secret
			$MFA_secret = trim( get_user_option( 'securio_mfa_secret', $user->ID ) );
			
			// Figure out if user is using relaxed mode ?
			$MFA_relaxedmode = trim( get_user_option( 'securio_mfa_relaxedmode', $user->ID ) );
			
			// Get the verification code entered by the user trying to login
			$otp = trim( $_POST[ 'securio_mfa_otp' ] );
		
			// Valid code ?
			if ( $this->verify( $MFA_secret, $otp, $MFA_relaxedmode ) ) {
				return $userstate;
			} else {
				// No, lets see if an app password is enabled, and this is an XMLRPC / APP login ?
				if ( trim( get_user_option( 'securio_mfa_pwdenabled', $user->ID ) ) == 'enabled' && ( defined('XMLRPC_REQUEST') || defined('APP_REQUEST') ) ) {
					$MFA_passwords 	= json_decode(  get_user_option( 'securio_mfa_passwords', $user->ID ) );
					$passwordsha1	= trim($MFA_passwords->{'password'} );
					$usersha1		= $this->hash( strtoupper( str_replace( ' ', '', $password ) ) );
					if ( $passwordsha1 == $usersha1 ) {
						return new WP_User( $user->ID );
					} else {
						// Wrong XMLRPC/APP password !
						return new WP_Error( 'invalid_securio_mfa_password', __( '<strong>ERROR</strong>: The Securio Multi-Factor password is incorrect.', 'google-authenticator' ) );
					} 		 
				} else {
					return new WP_Error( 'invalid_securio_mfa_token', __( '<strong>ERROR</strong>: The Securio Multi-Factor code is incorrect or has expired.', 'google-authenticator' ) );
				}	
			}
		}		
		// Securio Multi-Factor isn't enabled for this account,
		// just resume normal authentication.
		return $userstate;
	}

	// Generate New secret fropm AJAX
	function ajax_callback() {
		global $user_id;

		// Verify the NONCE
		check_ajax_referer( 'SecurioMFAaction', 'nonce' );
		
		// Generate Seed
		$secret = $this->create_secret();

		// Display
		$result = array( 'new-secret' => $secret );
		header( 'Content-Type: application/json' );
		echo json_encode( $result );

		// dont show rest of wordpress Page
		die(); 
	}

}

// So we dont cause errors when turning plugin on
if( ! function_exists('wp_authenticate') ){
	function wp_authenticate($username, $password) {
		global $Securio_BruteForce;
		return $Securio_BruteForce->wp_authenticate($username, $password);
	}
}

?>
