<?php

namespace League\Flysystem\Encryption;

use League\Flysystem\Config;
use League\Flysystem\Encryption\Exception\EncryptionException;
use League\Flysystem\FileAttributes;
use League\Flysystem\FilesystemAdapter;
use League\Flysystem\FilesystemException;
use League\Flysystem\UnableToReadFile;
use League\Flysystem\UnableToRetrieveMetadata;
use League\Flysystem\UnableToWriteFile;
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\FileAccessDenied;
use ParagonIE\Halite\Alerts\HaliteAlertInterface;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\File;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Stream\MutableFile;
use ParagonIE\Halite\Stream\WeakReadOnlyFile;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

/**
 * Class EncryptionAdapter
 */
class EncryptionAdapter implements FilesystemAdapter
{
    private FilesystemAdapter $adapter;
    private EncryptionKey $encryptionKey;

    /**
     * EncryptionAdapter constructor.
     *
     * @param FilesystemAdapter    $adapter       Decorated adapter
     * @param string|EncryptionKey $encryptionKey File path, raw key or EncryptionKey instance
     *
     * @throws InvalidKey
     * @throws CannotPerformOperation|\SodiumException Throwned if the key file is not readable
     */
    public function __construct(FilesystemAdapter $adapter, EncryptionKey|string $encryptionKey)
    {
        $this->adapter = $adapter;
        if ($encryptionKey instanceof EncryptionKey) {
            $this->encryptionKey = $encryptionKey;
        } elseif (\is_file($encryptionKey)) {
            $this->encryptionKey = KeyFactory::loadEncryptionKey($encryptionKey);
        } else {
            $this->encryptionKey = new EncryptionKey(new HiddenString($encryptionKey, true, true));
        }
    }

    public function getDecoratedAdapted(): FilesystemAdapter
    {
        return $this->adapter;
    }

    /**
     * Write a new file.
     *
     * @param string $path
     * @param string $contents
     * @param Config $config Config object
     *
     * @throws EncryptionException
     * @throws UnableToWriteFile
     * @throws FilesystemException
     */
    public function write(string $path, string $contents, Config $config): void
    {
        $encryptedContents = $this->encryptString($contents);
        if (false === $encryptedContents) {
            throw new EncryptionException();
        }

        $this->adapter->write($path, $encryptedContents, $config);
    }

    /**
     * Write a new file using a stream.
     *
     * @param string   $path
     * @param resource $contents
     * @param Config   $config Config object
     *
     * @throws EncryptionException
     * @throws UnableToWriteFile
     * @throws FilesystemException
     */
    public function writeStream(string $path, $contents, Config $config): void
    {
        $encryptedResource = $this->encryptStream($contents);
        if (false === $encryptedResource) {
            throw new EncryptionException();
        }

        $this->adapter->writeStream($path, $encryptedResource, $config);
    }

    /**
     * Read a file.
     *
     * @param string $path
     *
     * @return string File content
     *
     * @throws EncryptionException
     * @throws UnableToReadFile
     * @throws FilesystemException
     */
    public function read(string $path): string
    {
        $result = $this->adapter->read($path);
        $decryptedContents = $this->decryptString($result);
        if (false === $decryptedContents) {
            throw new EncryptionException();
        }

        return $decryptedContents;
    }

    /**
     * Read a file as a stream.
     *
     * @return resource File content as stream.
     *
     * @throws EncryptionException
     * @throws UnableToReadFile
     * @throws FilesystemException
     */
    public function readStream(string $path)
    {
        $result = $this->adapter->readStream($path);
        $decryptedResource = $this->decryptStream($result);
        if (false === $decryptedResource) {
            throw new EncryptionException();
        }

        return $decryptedResource;
    }

    /**
     * Get the size of a file.
     *
     * @param string $path
     *
     * @return FileAttributes
     *
     * @throws UnableToRetrieveMetadata
     * @throws FilesystemException
     */
    public function fileSize(string $path): FileAttributes
    {
        try {
            $file = $this->read($path);

            return new FileAttributes($path, \strlen($file));
        } catch (UnableToReadFile | EncryptionException) {
            throw UnableToRetrieveMetadata::create($path, 'file');
        }
    }

    /**
     * Get the mimetype of a file.
     *
     * @param string $path
     *
     * @return FileAttributes
     *
     * @throws UnableToRetrieveMetadata
     * @throws FilesystemException
     */
    public function mimeType(string $path): FileAttributes
    {
        return $this->adapter->mimeType($path);
    }

    public function fileExists(string $path): bool
    {
        return $this->adapter->fileExists($path);
    }

    public function directoryExists(string $path): bool
    {
        return $this->adapter->directoryExists($path);
    }

    public function delete(string $path): void
    {
        $this->adapter->delete($path);
    }

    public function deleteDirectory(string $path): void
    {
        $this->adapter->deleteDirectory($path);
    }

    public function createDirectory(string $path, Config $config): void
    {
        $this->adapter->createDirectory($path, $config);
    }

    public function setVisibility(string $path, string $visibility): void
    {
        $this->adapter->setVisibility($path, $visibility);
    }

    public function visibility(string $path): FileAttributes
    {
        return $this->adapter->visibility($path);
    }

    public function lastModified(string $path): FileAttributes
    {
        return $this->adapter->lastModified($path);
    }

    public function listContents(string $path, bool $deep): iterable
    {
        return $this->adapter->listContents($path, $deep);
    }

    public function move(string $source, string $destination, Config $config): void
    {
        $this->adapter->move($source, $destination, $config);
    }

    public function copy(string $source, string $destination, Config $config): void
    {
        $this->adapter->copy($source, $destination, $config);
    }

    /**
     * Encrypts a string.
     *
     * @param string $contents The string to encrypt.
     *
     * @return string|false false on failure, the encrypted string on success.
     */
    protected function encryptString(string $contents): string|false
    {
        $resource = $this->getStreamFromString($contents);
        if (false === $resource) {
            return false;
        }

        $encryptedStream = $this->encryptStream($resource);
        if (false === $encryptedStream) {
            return false;
        }

        return \stream_get_contents($encryptedStream);
    }

    /**
     * Encrypts a stream.
     *
     * @param resource $inputStream The resource to encrypt.
     *
     * @return resource|false false on failure, the encrypted stream on success.
     */
    protected function encryptStream($inputStream)
    {
        $tmpResource = \fopen('php://temp', 'r+b');
        if (false === $tmpResource) {
            return false;
        }

        try {
            try {
                // ReadOnlyFile does not support Guzzle Stream fopen() mode
                $input = new WeakReadOnlyFile($inputStream);
                $output = new MutableFile($tmpResource);
                File::encrypt($input, $output, $this->encryptionKey);
                $input->reset();
                $output->reset();
            } catch (FileAccessDenied) {
                $tempInputStream = \fopen('php://memory', 'r+b');
                if (false === $tempInputStream) {
                    return false;
                }
                \stream_copy_to_stream($inputStream, $tempInputStream);
                \fseek($tempInputStream, \ftell($inputStream));
                \fclose($tmpResource);
                $tmpResource = $this->encryptStream($tempInputStream);
                \fclose($tempInputStream);
            }
        } catch (HaliteAlertInterface | \SodiumException) {
            \rewind($inputStream);
            if (\is_resource($tmpResource)) {
                \fclose($tmpResource);
            }

            return false;
        }

        return $tmpResource;
    }

    /**
     * Decrypts a string.
     *
     * @param string $contents The string to decrypt.
     *
     * @return string|false false on failure, the decrypted string on success.
     */
    protected function decryptString(string $contents): string|false
    {
        $resource = $this->getStreamFromString($contents);
        if (false === $resource) {
            return false;
        }

        $decryptedStream = $this->decryptStream($resource);
        if (false === $decryptedStream) {
            return false;
        }

        return \stream_get_contents($decryptedStream);
    }

    /**
     * Decrypts a stream.
     *
     * @param resource $inputStream The resource to decrypt.
     *
     * @return resource|false false on failure, the decrypted stream on success.
     */
    protected function decryptStream($inputStream)
    {
        $tmpResource = \fopen('php://memory', 'r+b');
        if (false === $tmpResource) {
            return false;
        }

        try {
            try {
                // ReadOnlyFile does not support Guzzle Stream fopen() mode
                $input = new WeakReadOnlyFile($inputStream);
                $output = new MutableFile($tmpResource);
                File::decrypt($input, $output, $this->encryptionKey);
                $input->reset();
                $output->reset();
            } catch (FileAccessDenied) {
                $tempInputStream = \fopen('php://memory', 'r+b');
                if (false === $tempInputStream) {
                    return false;
                }
                \stream_copy_to_stream($inputStream, $tempInputStream);
                \fseek($tempInputStream, \ftell($inputStream));
                \fclose($tmpResource);
                $tmpResource = $this->decryptStream($tempInputStream);
                \fclose($tempInputStream);
            }
        } catch (HaliteAlertInterface | \SodiumException) {
            \rewind($inputStream);
            if (\is_resource($tmpResource)) {
                \fclose($tmpResource);
            }

            return false;
        }

        return $tmpResource;
    }

    /**
     * Returns a stream representation of a string.
     *
     * @param string $contents Contents in string format.
     *
     * @return resource|false false on failure, the stream with the string contents on success.
     */
    protected function getStreamFromString(string $contents)
    {
        $resource = \fopen('php://memory', 'r+b');
        if (false === $resource) {
            return false;
        }

        \fwrite($resource, $contents);
        \rewind($resource);

        return $resource;
    }

}
