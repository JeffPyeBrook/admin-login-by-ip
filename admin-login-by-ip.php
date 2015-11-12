<?php

/*
Plugin Name: Restrict Admin Login
Plugin URI: www.pyebrook.com
Description: Restrict administrator login to specific IP addresses
Version: 1.0
Author: Jeffrey
Author URI: www.pyebrook.com
License: GPL2
*/


add_filter( 'wp_authenticate_user', 'restrict_admin_login_by_ip', 10, 2 );
function restrict_admin_login_by_ip( $user, $password  ) {

	if ( empty( $password ) ) {
		// this should not happen?
	}

	if ( is_a( $user, 'WP_User' ) ) {

		if ( $user->has_cap( 'administrator' ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];

			$hostname = '';

			if ( function_exists( 'gethostbyaddr' ) ) {
				$hostname = gethostbyaddr( $ip );
			}

			if ( empty( $hostname ) ) {
				$hostname = '(unknown host)';
			}

			$allowed_ips = array(
				'127.0.0.1',
				'192.168.1.7',
				'192.168.1.5',
				'173.48.255.21', // pool-173-48-255-21.bstnma.fios.verizon.net
				'173.76.20.67',
				'70.192.17.93',
				'65.255.53.164',
			);
			if ( in_array( $ip, $allowed_ips ) ) {
				error_log( 'Validated administrator user ' . $user->user_login . ' login from ' . $hostname . '(' . $ip . ')' );
			} else {
				$user     = new WP_Error( 'Invalid Login', __( 'Login attempt for user "' . $user->user_login . '" from ' . $hostname . '(' . $ip . ')' . ' refused by ' . get_site_url() ) );
				$messages = $user->get_error_messages();
				foreach ( $messages as $message ) {
					error_log( $message );
				}
			}
		}
	}

	return $user;
}

add_filter( 'muplugins_loaded', 'pbci_early_check_for_access', 1 );

function pbci_early_check_for_access() {
	if ( is_current_script_restricted() ) {
		if ( ! is_current_ip_allowed() ) {
			header( 'HTTP/1.0 403 Forbidden' );
			echo 'HTTP/1.0 403 Forbidden';
			exit( 0 );
		}
	}
}

function is_current_script_restricted() {

	$restricted_scripts = array(
		'wp-login.php',
		'xmlrpc.php',
	);

	foreach( $restricted_scripts as $restricted_script_name ) {
		if ( current_uri_ends_with_script_name( $restricted_script_name ) ) {
			return true;
		}
	}

	return false;
}

function current_uri_ends_with_script_name( $script_name ) {

	$request_uri = $_SERVER[ 'REQUEST_URI' ];

	$request_uri_string_length = strlen( $request_uri );
	$script_name_string_length =  strlen( $script_name ) ;

	if ( $script_name_string_length > $request_uri_string_length ) {
		$result = false;
	} else {
		$result = substr_compare( $request_uri,
				$script_name,
				$request_uri_string_length - $script_name_string_length,
				$script_name_string_length) === 0;
	}

	return $result ;
}

function is_current_ip_allowed() {

	$ip = $_SERVER['REMOTE_ADDR'];

	$allowed_ips = array(
		'127.0.0.1',
		'192.168.1.',
		'192.168.1.7',
		'192.168.1.5',
		'173.76.20.67',
	);

	$ip_is_allowed = false;

	foreach( $allowed_ips as $allowed_ip ) {
		if ( $allowed_ip === substr( $ip, 0, strlen( $allowed_ip ) ) ) {
			$ip_is_allowed = true;
			break;
		}
	}

	$hostname = '';

	if ( function_exists( 'gethostbyaddr' ) ) {
		$hostname = gethostbyaddr( $ip );
	}

	if ( empty( $hostname ) ) {
		$hostname = '(unknown host)';
	}

	if ( $ip_is_allowed ) {
		$message  = 'IP address ' . $ip . ' (' . $hostname . ')' . ' is permitted to access restricted script ' . $_SERVER[ 'REQUEST_URI' ];
	} else {
		$message  = 'IP address ' . $ip . ' (' . $hostname . ')' . ' IS NOT permitted to access restricted script. '  . $_SERVER[ 'REQUEST_URI' ];
	}

	error_log( $message );

	return $ip_is_allowed;
}
