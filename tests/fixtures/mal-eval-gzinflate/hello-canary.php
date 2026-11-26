<?php
/*
Plugin Name: Hello Canary
*/
// INERT TEST FIXTURE: the decoded payload is echo 'CANARY_inert_payload';
@eval(gzinflate(base64_decode('S03OyFdQd3b0cwyKjM/MSy0qiS9IrMzJT0xRtwYA')));
