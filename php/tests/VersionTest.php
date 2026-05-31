<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Itcrow\Uacryptex\Uacryptex;

$version = Uacryptex::libraryVersion();
if ($version !== Uacryptex::VERSION) {
    fwrite(STDERR, "expected version " . Uacryptex::VERSION . ", got {$version}\n");
    exit(1);
}

echo "OK: {$version}\n";
