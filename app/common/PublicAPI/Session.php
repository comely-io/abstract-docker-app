<?php
declare(strict_types=1);

namespace App\Common\PublicAPI;

use App\Common\Database\AbstractAppModel;
use App\Common\Database\PublicAPI\Sessions;
use App\Common\Exception\AppException;
use App\Common\Security;
use App\Common\Users\User;
use Comely\Buffer\Buffer;

/**
 * Class Session
 * @package App\Common\PublicAPI
 * @property bool|null $checksumHealth
 * @property string|null $partialToken
 */
class Session extends AbstractAppModel
{
    public const TABLE = Sessions::TABLE;
    public const SERIALIZABLE = false;

    /** @var int */
    public int $id;
    /** @var string */
    public string $type;
    /** @var int */
    public int $archived;
    /** @var string */
    public string $ipAddress;
    /** @var string */
    public string $userAgent;
    /** @var string */
    public string $fingerprint;
    /** @var int|null */
    public ?int $authUserId = null;
    /** @var int|null */
    public ?int $authSessionOtp = null;
    /** @var string|null */
    public ?string $last2faCode = null;
    /** @var int|null */
    public ?int $last2faOn = null;
    /** @var int|null */
    public ?int $lastRecaptchaOn = null;
    /** @var int */
    public int $issuedOn;
    /** @var int */
    public int $lastUsedOn;

    /**
     * @return Buffer
     * @throws AppException
     */
    public function checksum(): Buffer
    {
        $token = $this->private("token");
        if (!is_string($token) || strlen($token) !== 32) {
            throw new \UnexpectedValueException('Session token not set for checksum; or is not 32 bytes');
        }

        $raw = sprintf(
            "%d:%s:%s:%d:%d:%s:%d:%d",
            $this->id,
            strtolower($this->type),
            $token,
            $this->authUserId ?? 0,
            $this->authSessionOtp ?? 0,
            strtolower($this->ipAddress),
            $this->issuedOn,
            $this->lastUsedOn
        );

        try {
            return $this->aK->ciphers->primary()->pbkdf2("sha1", $raw, Security::PBKDF2_Iterations($this->id, self::TABLE));
        } catch (\Exception $e) {
            $this->aK->errors->triggerIfDebug($e);
            throw new AppException(sprintf('Failed to compute public API session %d checksum', $this->id));
        }
    }

    /**
     * @param User $user
     * @param bool $otpChecked
     * @return void
     * @throws AppException
     */
    public function authenticateAs(User $user, bool $otpChecked = false): void
    {
        if ($this->authUserId) {
            throw new AppException('Cannot re-authenticate a session');
        }

        $this->authUserId = $user->id;
        $this->authSessionOtp = $otpChecked ? 1 : 0;
        $this->set("checksum", $this->checksum()->raw());
    }
}
