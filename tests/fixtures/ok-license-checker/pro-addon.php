<?php
/**
 * Plugin Name: Pro Addon
 * Plugin URI: https://proaddon-vendor.example/
 * Author URI: https://proaddon-vendor.example/
 */
add_action( 'admin_init', 'pa_check_license' );
function pa_check_license() {
	$r = wp_remote_post( 'https://api.proaddon-vendor.example/v1/license', array( 'body' => array(
		'key' => get_option( 'pa_license_key' ), 'site' => home_url(), 'email' => get_option( 'admin_email' ),
		'php' => PHP_VERSION, 'wp' => get_bloginfo( 'version' ) ) ) );
	$body = json_decode( wp_remote_retrieve_body( $r ), true );
	update_option( 'pa_license_status', isset( $body['status'] ) ? $body['status'] : 'invalid' );
}
