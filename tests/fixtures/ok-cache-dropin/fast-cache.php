<?php
/* Plugin Name: Fast Cache */
register_activation_hook( __FILE__, 'fc_install_dropin' );
function fc_install_dropin() {
	$src = file_get_contents( __DIR__ . '/templates/advanced-cache.tpl' );
	file_put_contents( WP_CONTENT_DIR . '/advanced-cache.php', $src );
	$cfg = file_get_contents( ABSPATH . 'wp-config.php' );
	if ( strpos( $cfg, 'WP_CACHE' ) === false ) {
		file_put_contents( ABSPATH . 'wp-config.php', str_replace( '<?php', "<?php\ndefine('WP_CACHE', true);", $cfg ) );
	}
	file_put_contents( wp_upload_dir()['basedir'] . '/fast-cache/index.php', '<?php // Silence is golden.' );
}
