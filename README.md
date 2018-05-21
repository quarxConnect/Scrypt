# Scrypt
Native Scrypt-Implementation for PHP

## Usage
~~~ {.php}
require_once ('Scrypt.php');

$Scrypt = new Scrypt (/* N */ 1024, /* r */ 8, /* p */ 16, /* dkLen */ 64);
echo bin2hex ($Scrypt ('password', 'salt'));
~~~

## License
Copyright (C) 2018 Bernd Holzmüller

Licensed under the MIT license. This is free software: you are free to
change and redistribute it. There is NO WARRANTY, to the extent
permitted by law.
