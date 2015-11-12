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

add_filter('wp_authenticate_user', 'restrict_admin_login_by_ip',10,2);
function restrict_admin_login_by_ip ($user, $password) {

	if ( is_a( $user, 'WP_User') ) {

		if ( $user->has_cap( 'administrator' ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];

			if ( function_exists( 'gethostbyaddr' ) ) {
				$hostname = gethostbyaddr( $ip );
			} else {
				$hostname = '(unknown host)';
			}

			$allowed_ips = array(
				'127.0.0.1',
				'192.168.1.7',
				'192.168.1.58',
				'173.48.255.21', // pool-173-48-255-21.bstnma.fios.verizon.net
			);
			if ( in_array( $ip, $allowed_ips ) ) {
				error_log( 'Validated administrator user ' . $user->user_login . ' login from ' . $hostname . '(' . $ip . ')' );
			} else {
				$user = new WP_Error( 'Invalid Login', __( 'Login attempt for user <b>' . $user->user_login . '</b> from ' . $hostname . '(' . $ip . ')' . ' refused.' ) );
				error_log( $user->get_error_messages() );
			}
		}
	}

	return $user;
}