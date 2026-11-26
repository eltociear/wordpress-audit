<?php
/* Plugin Name: Antispam API */
function as_check( $email ) {
	$r = wp_remote_post( 'https://moderate.antispam-service.example/api', array( 'body' => array( 'auth_key' => get_option( 'as_key' ), 'sender_email' => $email ) ) );
	return json_decode( wp_remote_retrieve_body( $r ), true );
}
