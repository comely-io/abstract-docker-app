<?php
declare(strict_types=1);

namespace App\Common\PublicAPI;

use App\Common\Database\AbstractAppModel;
use App\Common\Database\PublicAPI\Queries;
use App\Common\Exception\AppException;
use Comely\Buffer\Buffer;

/**
 * Class Query
 * @package App\Common\PublicAPI
 */
class Query extends AbstractAppModel
{
    public const TABLE = Queries::TABLE;
    public const SERIALIZABLE = false;

    /** @var int */
    public int $id;
    /** @var string */
    public string $ipAddress;
    /** @var string */
    public string $method;
    /** @var string */
    public string $endpoint;
    /** @var float */
    public float $startOn;
    /** @var float|null */
    public ?float $endOn = null;
    /** @var null|int */
    public ?int $resCode = null;
    /** @var null|int */
    public ?int $resLen = null;
    /** @var int|null */
    public ?int $flagApiSess = null;
    /** @var null|int */
    public ?int $flagUserId = null;

    /** @var bool|null */
    public ?bool $checksumVerified = null;

    /**
     * @return void
     */
    public function beforeQuery(): void
    {
        if (strlen($this->endpoint) > 512) {
            $this->endpoint = substr($this->endpoint, 0, 512);
        }
    }

    /**
     * @return void
     * @throws AppException
     * @throws \Comely\Security\Exception\CipherException
     */
    public function validateChecksum(): void
    {
        if ($this->checksum()->raw() !== $this->private("checksum")) {
            throw new AppException(sprintf('Invalid checksum of public API query ray # %d', $this->id));
        }

        $this->checksumVerified = true;
    }

    /**
     * @return Buffer
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Security\Exception\CipherException
     */
    public function checksum(): Buffer
    {
        $raw = sprintf(
            '%d:%s:%s:%s:%s:%s:%s:%s:%d:%d',
            $this->id,
            $this->ipAddress,
            strtolower(trim($this->method)),
            strtolower(trim($this->endpoint)),
            $this->startOn,
            $this->endOn,
            $this->resCode ?? 0,
            $this->resLen ?? 0,
            $this->flagApiSess ?? 0,
            $this->flagUserId ?? 0
        );

        return $this->aK->ciphers->secondary()->pbkdf2("sha1", $raw, 1000);
    }
}
