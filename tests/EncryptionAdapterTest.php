<?php

namespace League\Flysystem\Encryption\Tests;

use League\Flysystem\AdapterTestUtilities\FilesystemAdapterTestCase;
use League\Flysystem\Config;
use League\Flysystem\Encryption\EncryptionAdapter;
use League\Flysystem\FilesystemAdapter;
use League\Flysystem\FilesystemException;
use League\Flysystem\Local\LocalFilesystemAdapter;
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\FileAccessDenied;
use ParagonIE\Halite\Alerts\FileError;
use ParagonIE\Halite\Alerts\FileModified;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Stream\ReadOnlyFile;
use ParagonIE\Halite\Stream\WeakReadOnlyFile;

/**
 * Class EncryptionAdapterTest
 */
final class EncryptionAdapterTest extends FilesystemAdapterTestCase
{
    /**
     * @param string|resource $resource
     *
     * @return bool
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidType
     * @throws \SodiumException
     */
    protected static function isEncrypted($resource): bool
    {
        $file = new WeakReadOnlyFile($resource);
        $file->reset();
        $header = $file->readBytes(Halite::VERSION_TAG_LEN);

        return \is_resource($resource) && \ord($header[0]) === 49 && \ord($header[1]) === 65;
    }

    /**
     * @throws InvalidKey
     * @throws CannotPerformOperation
     * @throws \SodiumException
     */
    protected static function createFilesystemAdapter(): FilesystemAdapter
    {
        $encryptionKey = KeyFactory::generateEncryptionKey();
        $decoratedAdapter = new LocalFilesystemAdapter(__DIR__.DIRECTORY_SEPARATOR.'tmp'.DIRECTORY_SEPARATOR);

        return new EncryptionAdapter($decoratedAdapter, $encryptionKey);
    }

    /**
     * @test
     *
     * @throws InvalidType
     * @throws FilesystemException
     * @throws \SodiumException
     * @throws FileModified
     * @throws FileAccessDenied
     * @throws FileError
     * @throws CannotPerformOperation
     */
    public function writingAnEncryptedFile(): void
    {
        $adapter = $this->adapter();
        $writeStream = stream_with_contents('contents');

        $adapter->writeStream('path.txt', $writeStream, new Config());

        if (\is_resource($writeStream)) {
            \fclose($writeStream);
        }

        $fileExists = $adapter->fileExists('path.txt');
        $this->assertTrue($fileExists);

        /** @var EncryptionAdapter $adapter */
        $adapter = $this->adapter();
        $encryptedStream = \stream_with_contents($adapter->getDecoratedAdapted()->read('path.txt'));
        $fileIsEncrypted = self::isEncrypted($encryptedStream);
        $this->assertTrue($fileIsEncrypted);
    }

    /**
     * @test
     *
     * @throws InvalidType
     * @throws FilesystemException
     * @throws \SodiumException
     * @throws FileModified
     * @throws FileAccessDenied
     * @throws FileError
     * @throws CannotPerformOperation
     */
    public function writingAnEncryptedStream(): void
    {
        $adapter = $this->adapter();
        $writeStream = stream_with_contents('contents');

        $adapter->writeStream('path.txt', $writeStream, new Config());

        if (\is_resource($writeStream)) {
            \fclose($writeStream);
        }

        $fileExists = $adapter->fileExists('path.txt');
        $this->assertTrue($fileExists);

        /** @var EncryptionAdapter $adapter */
        $adapter = $this->adapter();
        $fileIsEncrypted = self::isEncrypted($adapter->getDecoratedAdapted()->readStream('path.txt'));
        $this->assertTrue($fileIsEncrypted);
    }
}
