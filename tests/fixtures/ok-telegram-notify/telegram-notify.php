<?php
/* Plugin Name: Telegram Notify */
add_action( 'woocommerce_new_order', 'tn_send' );
function tn_send( $order_id ) {
	$token = get_option( 'tn_bot_token' );
	wp_remote_post( 'https://api.telegram.org/bot' . $token . '/sendMessage', array( 'body' => array( 'chat_id' => get_option( 'tn_chat' ), 'text' => 'New order #' . $order_id ) ) );
}
