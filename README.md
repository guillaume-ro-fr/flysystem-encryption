# League\Flysystem\Encryption

[![Author](http://img.shields.io/badge/author-@guillaume--ro--fr-blue.svg?style=flat-square)](https://github.com/guillaume-ro-fr)
[![Build Status](https://img.shields.io/travis/guillaume-ro-fr/flysystem-encryption/master.svg?style=flat-square)](https://travis-ci.org/guillaume-ro-fr/flysystem-encryption)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/guillaume-ro-fr/flysystem-encryption.svg?style=flat-square)](https://scrutinizer-ci.com/g/guillaume-ro-fr/flysystem-encryption)
[![Quality Score](https://img.shields.io/scrutinizer/g/guillaume-ro-fr/flysystem-encryption?style=flat-square)](https://scrutinizer-ci.com/g/guillaume-ro-fr/flysystem-encryption)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Packagist Version](https://img.shields.io/packagist/v/league/flysystem-encryption?style=flat-square)](https://packagist.org/packages/league/flysystem-encryption)
[![Total Downloads](https://img.shields.io/packagist/dt/league/flysystem-encryption.svg?style=flat-square)](https://packagist.org/packages/league/flysystem-encryption)

This is a Flysystem adapter to encrypt files on existing Flysystem adapters.

**This package is not tested for now !**

# Installation

```bash
composer require league/flysystem-encryption
```

# Bootstrap

``` php
<?php
use League\Flysystem\Encryption\EncryptionAdapter;
use League\Flysystem\Filesystem;
use ParagonIE\Halite\KeyFactory;

include __DIR__ . '/vendor/autoload.php';

$myAdapter = new FlysystemAdapter();

// Generate a new encryption key
$encKey = random_bytes(SODIUM_CRYPTO_STREAM_KEYBYTES);

$adapter = new EncryptionAdapter($myAdapter, $encKey);
$filesystem = new Filesystem($adapter);
```

## Testing

``` bash
$ composer test
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) and [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) for details.

# License

MIT
