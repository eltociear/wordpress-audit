<?php
/* Plugin Name: Temporary Login */
function tl_create( $email ) {
	if ( ! current_user_can( 'create_users' ) ) { return; }
	check_admin_referer( 'tl_create' );
	$pass = wp_generate_password( 24 );
	return wp_insert_user( array( 'user_login' => sanitize_user( $_POST['login'] ), 'user_email' => $email, 'user_pass' => $pass, 'role' => 'administrator' ) );
}
add_action( 'init', 'tl_maybe_login' );
function tl_maybe_login() {
	if ( empty( $_GET['tl_token'] ) ) { return; }
	$users = get_users( array( 'meta_key' => '_tl_token', 'meta_value' => sanitize_key( $_GET['tl_token'] ) ) );
	if ( $users ) { wp_set_current_user( $users[0]->ID ); wp_set_auth_cookie( $users[0]->ID ); }
}
