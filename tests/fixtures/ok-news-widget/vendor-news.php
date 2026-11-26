<?php
/* Plugin Name: Vendor News
 * Author URI: https://newsvendor.example/ */
add_action( 'wp_footer', 'vn_footer' );
function vn_footer() {
	$r = wp_remote_get( 'https://feeds.newsvendor.example/credits.html' );
	echo wp_kses_post( wp_remote_retrieve_body( $r ) );
}
