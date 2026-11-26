<?php
/* Plugin Name: Agency Branding */
add_filter( 'all_plugins', 'ab_hide' );
function ab_hide( $plugins ) {
	if ( get_option( 'ab_hide_from_list' ) && ! current_user_can( 'manage_network' ) ) {
		unset( $plugins[ plugin_basename( __FILE__ ) ] );
	}
	return $plugins;
}
