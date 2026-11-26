<?php
/* Plugin Name: Admin Editor */
function ae_save() {
	if ( ! current_user_can( 'edit_plugins' ) ) { return; }
	check_admin_referer( 'ae_save' );
	$upload = wp_upload_dir();
	$f = fopen( $upload['basedir'] . '/ae/index.php', 'w+' ); fclose( $f );
	$f = fopen( $upload['basedir'] . '/ae/custom.css', 'w+' );
	fwrite( $f, wp_unslash( $_POST['css'] ) );
	file_put_contents( WP_PLUGIN_DIR . '/' . sanitize_file_name( $_POST['folder'] ) . '/new.php', "<?php\n/* Plugin Name: " . $_POST['name'] . " */" );
}
