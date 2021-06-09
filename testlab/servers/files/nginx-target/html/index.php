<?php
session_set_cookie_params([
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'],
    'secure' => true,
    'httponly' => true,
]);

session_start();
?>
<h1>Very Important Page!</h1>
<b>In the background a cookie was set with session_id <?php echo session_id(); ?> for target.com</b>