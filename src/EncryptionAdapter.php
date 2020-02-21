<?php

namespace League\Flysystem\Encryption;

use League\Flysystem\AdapterDecorator\DecoratorTrait;
use League\Flysystem\AdapterInterface;
use League\Flysystem\Config;
use League\Flysystem\Util;
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
class EncryptionAdapter implements AdapterInterface
{
    use DecoratorTrait;

    /** @var AdapterInterface */
    private $adapter;

    /** @var EncryptionKey */
    private $encryptionKey;

    /**
     * EncryptionAdapter constructor.
     *
     * @param AdapterInterface     $adapter       Decorated adapter
     * @param string|EncryptionKey $encryptionKey File path, raw key or EncryptionKey instance
     *
     * @throws InvalidKey
     * @throws CannotPerformOperation Throwned if the key file is not readable
     */
    public function __construct(AdapterInterface $adapter, $encryptionKey)
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

    /**
     * Write a new file.
     *
     * @param string $path
     * @param string $contents
     * @param Config $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function write($path, $contents, Config $config)
    {
        $encryptedContents = $this->encryptString($contents);
        if (false === $encryptedContents) {
            return false;
        }

        return $this->adapter->write($path, $encryptedContents, $config);
    }

    /**
     * Write a new file using a stream.
     *
     * @param string   $path
     * @param resource $resource
     * @param Config   $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function writeStream($path, $resource, Config $config)
    {
        $encryptedResource = $this->encryptStream($resource);
        if (false === $encryptedResource) {
            return false;
        }

        return $this->adapter->writeStream($path, $encryptedResource, $config);
    }

    /**
     * Update a file.
     *
     * @param string $path
     * @param string $contents
     * @param Config $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function update($path, $contents, Config $config)
    {
        $encryptedContents = $this->encryptString($contents);
        if (false === $encryptedContents) {
            return false;
        }

        return $this->adapter->update($path, $encryptedContents, $config);
    }

    /**
     * Update a file using a stream.
     *
     * @param string   $path
     * @param resource $resource
     * @param Config   $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function updateStream($path, $resource, Config $config)
    {
        $encryptedResource = $this->encryptStream($resource);
        if (false === $encryptedResource) {
            return false;
        }

        return $this->adapter->updateStream($path, $encryptedResource, $config);
    }

    /**
     * Read a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function read($path)
    {
        $result = $this->adapter->read($path);
        if (false === $result) {
            return $result;
        }

        $contents = $result['contents'];
        if (!\is_string($contents)) {
            return false;
        }

        $decryptedContents = $this->decryptString($contents);
        if (false === $decryptedContents) {
            return false;
        }

        $result['contents'] = $decryptedContents;

        return $result;
    }

    /**
     * Read a file as a stream.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function readStream($path)
    {
        $result = $this->adapter->readStream($path);
        if (false === $result) {
            return false;
        }

        $stream = $result['stream'];
        if (!\is_resource($stream)) {
            return false;
        }

        $decryptedResource = $this->decryptStream($stream);
        if (false === $decryptedResource) {
            return false;
        }

        $result['stream'] = $decryptedResource;

        return $result;
    }

    /**
     * Get all the meta data of a file or directory.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getMetadata($path)
    {
        $metadata = $this->adapter->getMetadata($path);
        if (false === $metadata) {
            return false;
        }

        unset($metadata['size'], $metadata['mimetype']);

        return $metadata;
    }

    /**
     * Get all the meta data of a file or directory.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getSize($path)
    {
        $decryptedContent = $this->read($path);
        if (false === $decryptedContent) {
            return false;
        }

        return ['size' => Util::contentSize($decryptedContent['contents'])];
    }

    /**
     * Get the mimetype of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getMimetype($path)
    {
        return $this->adapter->getMimetype($path);
    }

    /**
     * Get the decorated adapter.
     *
     * @return AdapterInterface
     */
    protected function getDecoratedAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    /**
     * Encrypts a string.
     *
     * @param string $contents The string to encrypt.
     *
     * @return string|false false on failure, the encrypted string on success.
     */
    protected function encryptString(string $contents)
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
                // ReadOnlyFile does not support the Guzzle Stream fopen() mode
                $input = new WeakReadOnlyFile($inputStream);
                $output = new MutableFile($tmpResource);
                File::encrypt($input, $output, $this->encryptionKey);
                $input->reset();
                $output->reset();
            } catch (FileAccessDenied $ignored) {
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
        } catch (HaliteAlertInterface $ignored) {
            \rewind($inputStream);
            \fclose($tmpResource);

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
    protected function decryptString(string $contents)
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
                // ReadOnlyFile does not support the Guzzle Stream fopen() mode
                $input = new WeakReadOnlyFile($inputStream);
                $output = new MutableFile($tmpResource);
                File::decrypt($input, $output, $this->encryptionKey);
                $input->reset();
                $output->reset();
            } catch (FileAccessDenied $ignored) {
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
        } catch (HaliteAlertInterface $ignored) {
            \rewind($inputStream);
            \fclose($tmpResource);

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
