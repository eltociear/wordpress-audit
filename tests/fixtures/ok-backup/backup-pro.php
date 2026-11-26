<?php
/* Plugin Name: Backup Pro
 * Plugin URI: https://backup-vendor.example/ */
function bp_dump_db() {
	$cmd = sprintf( 'mysqldump -h%s -u%s -p%s %s', escapeshellarg( DB_HOST ), escapeshellarg( DB_USER ), escapeshellarg( DB_PASSWORD ), escapeshellarg( DB_NAME ) );
	exec( $cmd . ' > ' . escapeshellarg( bp_tmp() ), $out );
	wp_remote_post( 'https://content.dropboxapi.com/2/files/upload', array( 'body' => file_get_contents( bp_tmp() ) ) );
}
