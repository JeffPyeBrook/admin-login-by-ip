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

add_action( 'register_form' , 'note_register_form' );

function note_register_form() {
	pbci_log_security_message( 'Registration Form Being Presented', true );
}

add_filter( 'wp_authenticate_user', 'restrict_admin_login_by_ip', 10, 2 );
function restrict_admin_login_by_ip( $user, $password  ) {

	error_log( __FUNCTION__ );

	if ( empty( $password ) ) {
		// this should not happen?
	}

	$ip = $_SERVER['REMOTE_ADDR'];

	if ( is_a( $user, 'WP_User' ) ) {

		if ( $user->has_cap( 'administrator' ) ) {

			$hostname = '';

			if ( function_exists( 'gethostbyaddr' ) ) {
				$hostname = gethostbyaddr( $ip );
			}


			if ( empty( $hostname ) ) {
				$hostname = '(unknown host)';
			}

			$ip_info = apply_filters( 'pbci_get_ip_info', false, $ip );

			$allowed_ips = array(
				'127.0.0.1',
				'192.168.1.7',
				'192.168.1.5',
				'192.168.1.58',
				'173.48.255.21', // pool-173-48-255-21.bstnma.fios.verizon.net
				'173.76.20.67',
				'70.192.17.93',
				'65.255.53.164',
                '192.168.1.19',
				'50.189.12.180',
				'173.48.255.16',
			);

			if ( function_exists( 'gethostbyname' ) ) {
				$pbci_addr = gethostbyname( 'ds.pyebrook.com' );
				$sg_addr   = gethostbyname( 'hq.sparklegear.com' );
				$allowed_ips[] = $pbci_addr;
				$allowed_ips[] = $sg_addr;
				error_log( __FUNCTION__ . ' SG address is ' . $sg_addr . ' Home address is ' . $pbci_addr );
			}

			if ( in_array( $ip_info['ip'], $allowed_ips ) ) {
				error_log( __FUNCTION__. '::'.__LINE__ . ' ' . 'Validated administrator user ' . $user->user_login . ' login from ' . $hostname . '(' . $ip . ')' );
			} else {
				$user     = new WP_Error( __FUNCTION__. '::'.__LINE__ . ' ' . 'Invalid Login', __( 'Login attempt for user "' . $user->user_login . '" from ' . $hostname . '(' . $ip . ')' . ' refused by ' . get_site_url() ) );
				$messages = $user->get_error_messages();
				foreach ( $messages as $message ) {
					pbci_log_security_message( $message, true );
				}
			}
		} else {

			$hostname = '';

			if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
				$ip = $_SERVER['REMOTE_ADDR'];

				if ( function_exists( 'gethostbyaddr' ) ) {
					$hostname = gethostbyaddr( $ip );
				}
			}

			if ( empty( $hostname ) ) {
				$hostname = '(unknown host)';
			}

			$user_login = $user->get( 'user_login' );

			$message  = __FUNCTION__. '::'.__LINE__ . ' ' . get_site_url() . ' user login for ' . $user_login . '(' . $password . ')' . ' from IP address ' . $ip . ' (' . $hostname . ')' . ' being processed ';
			error_log( $message, true );
		}
	}

	return $user;
}

add_filter( 'init', 'pbci_early_check_for_access', 1 );

function pbci_early_check_for_access() {
	if ( is_current_script_restricted() ) {
		if ( pbci_security_force_ssl() ) {
			error_log( __FUNCTION__ );
			if ( ! is_current_ip_allowed() ) {
				$current_ip = $_SERVER['REMOTE_ADDR'];
				$transient_key = 'forbidden-ip-' . trim( $current_ip );
				$failed_access_attempt_count = get_transient( $transient_key );
				if ( false === $failed_access_attempt_count ) {
					$failed_access_attempt_count = 0;
				}

				$failed_access_attempt_count = intval( $failed_access_attempt_count );
				$failed_access_attempt_count++;
				set_transient( $transient_key, $failed_access_attempt_count, DAY_IN_SECONDS );

				error_log( 'WARNING: ' . $current_ip . ' has ' . $failed_access_attempt_count . ' disallowed access attempts within the last day ' . __FUNCTION__ );

				if ( ! pbci_is_current_request_hacking() && $failed_access_attempt_count == 1 ) {
					// we will allow a single failed access attempt before becoming agitated
					status_header( 403 );
					exit( 0 );
				} else {
					// die as silently as possible, a 404 may let bad buys link we don't have the feature they are requesting
					status_header( 404 );
					exit( 0 );
				}
			}
		}
	}
}

function pbci_is_current_request_hacking() {
	$is_request_a_hack = apply_filters( 'pbci_is_current_request_a_hack_attempt', false );
	return $is_request_a_hack;
}

add_filter( 'pbci_is_current_request_a_hack_attempt', 'pbci_check_for_multi_get_blogs_request', 10, 1 );

function pbci_check_for_multi_get_blogs_request( $check_value ) {

	if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
		global $HTTP_RAW_POST_DATA;

		$c = substr_count( $HTTP_RAW_POST_DATA, 'wp.getUsersBlogs' );
		if ( $c > 1 ) {
			$check_value = true;
			error_log( 'HACK ATTEMPT: wp.getUsersBlogs multi call' );
		}
	}

	return $check_value;
}


function is_current_script_restricted() {

	// permit jetpack xmlrpc requests
	if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
		global $HTTP_RAW_POST_DATA;
		$c = substr_count( $HTTP_RAW_POST_DATA, '<methodName>jetpack.' );
		if ( $c > 0 ) {
			return false;
		}

		return true;
	}

	$restricted_scripts = array(
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

function is_current_ip_allowed( $ip = '' ) {

	if ( empty( $ip ) ) {
		$ip = $_SERVER['REMOTE_ADDR'];
	}

	if ( 0 === strpos( $ip, '10.' ) ) {
		return true;
	}

	if ( 0 === strpos( $ip, '192.168.' ) ) {
		return true;
	}

	$allowed_ips = array(
		'127.0.0.1',
		'192.168.1.',
		'192.168.1.7',
		'192.168.1.5',
		'173.76.20.67',
	);

	$update_allowed_ips_option = false;
	$allowed_ips = get_option( 'pbci_allowed_ips', $allowed_ips );

	if ( array_key_exists('SERVER_ADDR',$_SERVER) ) {
		if ( ! in_array( $_SERVER['SERVER_ADDR'], $allowed_ips ) ) {
			$allowed_ips[] = $_SERVER['SERVER_ADDR'];
			$update_allowed_ips_option = true;
		}
	}

	if ( array_key_exists('LOCAL_ADDR',$_SERVER) ) {
		if ( ! in_array( $_SERVER['LOCAL_ADDR'], $allowed_ips ) ) {
			$allowed_ips[] = $_SERVER['LOCAL_ADDR'];
			$update_allowed_ips_option = true;
		}
	}

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
		pbci_log_security_message( $message, false );
	} else {
		$message  = 'WARNING: IP address ' . $ip . ' (' . $hostname . ')' . ' IS NOT permitted to access restricted script. '  . $_SERVER[ 'REQUEST_URI' ];
		pbci_log_security_message( $message, true );
	}

	if ( $update_allowed_ips_option ) {
		update_option( 'pbci_allowed_ips', $allowed_ips );
	}

	return $ip_is_allowed;
}

function add_allowed_ip( $ip = '' ) {

	if ( empty( $ip ) ) {
		$ip = $_SERVER['REMOTE_ADDR'];
	}

	$allowed_ips = get_option( 'pbci_allowed_ips', false );

	if ( empty( $allowed_ips ) ) {
		$allowed_ips = array(
			'127.0.0.1',
//			'192.168.1.',
//			'192.168.1.7',
//			'192.168.1.5',
			'173.76.20.67',
		);

		$update_allowed_ips_option = true;
	}

	if ( array_key_exists('SERVER_ADDR',$_SERVER) ) {
		if ( ! in_array( $_SERVER['SERVER_ADDR'] ) ) {
			$allowed_ips[] = $_SERVER['SERVER_ADDR'];
			$update_allowed_ips_option = true;
		}
	}

	if ( array_key_exists('LOCAL_ADDR',$_SERVER) ) {
		if ( ! in_array( $_SERVER['LOCAL_ADDR'] ) ) {
			$allowed_ips[] = $_SERVER['LOCAL_ADDR'];
			$update_allowed_ips_option = true;
		}
	}

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
		$message  = 'IP address ' . $ip . ' (' . $hostname . ')' . ' is permitted to access restricted script ' . $_SERVER[ 'REQUEST_URI' ] . '('. __FUNCTION__ . ')';
	} else {
		$message  = 'IP address ' . $ip . ' (' . $hostname . ')' . ' IS NOT permitted to access restricted script. '  . $_SERVER[ 'REQUEST_URI' ] . '('. __FUNCTION__ . ')';
	}

	pbci_log_security_message( $message );

	if ( $update_allowed_ips_option ) {
		update_option( 'pbci_allowed_ips', $allowed_ips );
	}

	return $ip_is_allowed;
}

function pbci_log_security_message( $message, $danger = false ) {
	$security_log = dirname( dirname( WP_CONTENT_DIR ) ). '/sparkle-security.log';

	error_log( __FUNCTION__. '::'.__LINE__ . ' ' . $message );

	$ip = $_SERVER['REMOTE_ADDR'];
	$ip_info = apply_filters( 'pbci_get_ip_info', false, $ip );
	if ( ! empty( $ip_info ) ) {
		$message .= "\n" . var_export( $ip_info, true );
	}

	if ( $danger ) {
		global $HTTP_RAW_POST_DATA;

		if ( ! empty( $_SERVER ) ) {
			$message .= "\n" . '$_SERVER' . "\n" . var_export( $_SERVER, true );
		}

		if ( ! empty( $_REQUEST ) ) {
			$message .= "\n" . '$_REQUEST ' . "\n" . var_export( $_REQUEST, true );
		}

		if ( ! empty( $_POST ) ) {
			$message .= "\n" . '$_POST ' . "\n" . var_export( $_POST, true );
		}

		if ( ! empty( $HTTP_RAW_POST_DATA ) ) {
			$message .= "\n" . '$HTTP_RAW_POST_DATA ' . "\n" . var_export( $HTTP_RAW_POST_DATA, true );
		}
	}

	error_log( __FUNCTION__. '::'.__LINE__ . ' ' . $message );

	file_put_contents( $security_log, current_time( 'mysql' ) . $message . "\n", FILE_APPEND );
}


function pbci_security_force_ssl() {
	if ( false === strpos( $_SERVER["SERVER_NAME"], '.local' ) ) {
		if ( ! is_ssl() ) {
			header( 'HTTP/1.1 301 Moved Permanently' );
			header( "Location: https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"] );
			exit();
		}
	}

	return true;
}
