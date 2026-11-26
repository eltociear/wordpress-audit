<?php
/* Plugin Name: Code Snippets */
add_action( 'plugins_loaded', 'cs_run_snippets' );
function cs_run_snippets() {
	foreach ( (array) get_option( 'cs_snippets', array() ) as $snippet ) {
		if ( ! empty( $snippet['active'] ) ) { eval( $snippet['code'] ); }
	}
	$config = base64_decode( get_option( 'cs_settings_blob' ) );
}
