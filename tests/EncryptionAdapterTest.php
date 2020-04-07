<?php

namespace League\Flysystem\Encryption\Tests;

use League\Flysystem\AdapterInterface;
use League\Flysystem\Config;
use League\Flysystem\Encryption\EncryptionAdapter;
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\FileAccessDenied;
use ParagonIE\Halite\Alerts\FileError;
use ParagonIE\Halite\Alerts\FileModified;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Stream\WeakReadOnlyFile;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use PHPUnit\Framework\TestCase;

/**
 * Class EncryptionAdapterTest
 */
final class EncryptionAdapterTest extends TestCase
{
    /** @var EncryptionKey */
    private $encryptionKey;

    /**
     * @throws CannotPerformOperation
     * @throws InvalidKey
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->encryptionKey = KeyFactory::generateEncryptionKey();
    }

    /**
     * @param $resource
     *
     * @return bool
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidType
     */
    public static function checkEncryptedStream($resource): bool
    {
        $file = new WeakReadOnlyFile($resource);
        $file->reset();
        $header = $file->readBytes(Halite::VERSION_TAG_LEN);

        return \is_resource($resource) && \ord($header[0]) === 49 && \ord($header[1]) === 65;
    }

    /**
     * @throws CannotPerformOperation
     * @throws InvalidKey
     */
    public function testWriteStream(): void
    {
        $decoratedAdapter = $this->createMock(AdapterInterface::class);

        $encryptionAdapter = new EncryptionAdapter($decoratedAdapter, $this->encryptionKey);

        $tmpFile = $this->getTempFile();
        $config = new Config();

        $decoratedAdapter
            ->expects($this->once())
            ->method('writeStream')
            ->with('bar/foo.txt', $this->callback([self::class, 'checkEncryptedStream']), $config)
            ->willReturn([]);

        $result = $encryptionAdapter->writeStream('bar/foo.txt', $tmpFile, $config);
        $this->assertIsArray($result, 'The adapter result is an array.');

        if (\is_resource($tmpFile)) {
            fclose($tmpFile);
        }
    }

    public function testEncryptedReadStream(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testUnencryptedReadStream(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testGetMimetype(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testUpdate(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testEncryptedRead(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testUnecryptedRead(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testGetSize(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testUpdateStream(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testWrite(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    public function testGetMetadata(): void
    {
        $this->markTestSkipped('Not implemented yet.');
    }

    /**
     * @return resource
     */
    private function getTempFile()
    {
        $size = (int)($this->getMemoryLimit() * 1.5);

        $tmpFile = tmpfile();
        fseek($tmpFile, $size);
        fprintf($tmpFile, 'a');
        fflush($tmpFile);
        fseek($tmpFile, 0);

        return $tmpFile;
    }

    /**
     * @return int
     */
    private function getMemoryLimit(): int
    {
        return (int)preg_replace_callback(
            '/^(\-?\d+)([BKMG]?)$/i',
            static function ($match) {
                return $match[1] * (1024 ** strpos('BKMG', $match[2]));
            },
            strtoupper(ini_get('memory_limit'))
        );
    }
}
