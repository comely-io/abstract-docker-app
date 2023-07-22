<?php
declare(strict_types=1);

namespace App\Common\Users;

use App\Common\Database\AbstractAppModel;
use App\Common\Database\Primary\Users\Profiles;
use App\Common\Exception\AppException;
use Comely\Buffer\Buffer;
use Comely\Security\Exception\CipherException;

/**
 * Class Profile
 * @package App\Common\Users
 */
class Profile extends AbstractAppModel
{
    public const TABLE = Profiles::TABLE;
    public const SERIALIZABLE = true;

    /** @var int */
    public int $userId;
    /** @var int */
    public int $idVerified = 0;
    /** @var int */
    public int $addressVerified = 0;
    /** @var string|null */
    public ?string $firstName = null;
    /** @var string|null */
    public ?string $lastName = null;
    /** @var string|null */
    public ?string $gender = null;
    /** @var string|null */
    public ?string $address1 = null;
    /** @var string|null */
    public ?string $address2 = null;
    /** @var string|null */
    public ?string $postalCode = null;
    /** @var string|null */
    public ?string $city = null;
    /** @var string|null */
    public ?string $state = null;

    /** @var bool */
    public bool $_checksumValidated = false;
    /** @var bool */
    public bool $isRegistered = false;
    /** @var int|null  */
    public ?int $dobTs = null;
    /** @var array|null  */
    public ?array $dobDate = null;

    /**
     * @return void
     * @throws AppException
     */
    public function validateChecksum(): void
    {
        if ($this->checksum()->raw() !== $this->private("checksum")) {
            throw new AppException(sprintf('User profile %d checksum validation failed', $this->userId));
        }

        $this->_checksumValidated = true;
    }

    /**
     * @return Buffer
     * @throws AppException
     */
    public function checksum(): Buffer
    {
        $this->calibrateInternalProps();
        $dob = $this->private("dob");
        $raw = sprintf(
            "%d:%d:%d:%s:%s:%s:%s:%s:%s:%s:%s:%s",
            $this->userId,
            $this->idVerified,
            $this->addressVerified,
            $this->firstName ? trim($this->firstName) : null,
            $this->lastName ? trim($this->lastName) : null,
            $this->gender ? trim($this->gender) : null,
            $dob ? trim($dob) : null,
            $this->address1 ? trim($this->address1) : null,
            $this->address2 ? trim($this->address2) : null,
            $this->postalCode ? trim($this->postalCode) : null,
            $this->city ? trim($this->city) : null,
            $this->state ? trim($this->state) : null,
        );

        try {
            return $this->aK->ciphers->users()->pbkdf2("sha1", $raw, 100);
        } catch (CipherException $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AppException(sprintf('Failed to compute user profile %d checksum', $this->userId));
        }
    }

    /**
     * @return void
     * @throws AppException
     */
    private function calibrateInternalProps(): void
    {
        $this->idVerified = $this->idVerified === 1 ? 1 : 0;
        $this->addressVerified = $this->addressVerified === 1 ? 1 : 0;
        if ($this->gender && !in_array($this->gender, ["m", "f", "o"])) {
            throw new AppException(sprintf('Invalid user profile %d gender', $this->userId));
        }

        $dob = $this->private("dob");
        if (is_string($dob) && !$dob) {
            $this->set("dob", null); // replace empty string "" with a NULL
        }

        if ($dob && !preg_match('/^\d{8}$/', $dob)) {
            throw new AppException(sprintf('Invalid user profile %d DOB', $this->userId));
        }
    }

    /**
     * @return void
     * @throws AppException
     */
    public function beforeQuery(): void
    {
        $this->calibrateInternalProps();
    }

    /**
     * @return int|null
     */
    public function dob(): ?int
    {
        $dob = $this->private("dob");
        if ($dob) {
            $ts = mktime(0, 0, 0, (int)substr($dob, 2, 2), (int)substr($dob, 0, 2), (int)substr($dob, 4));
            if ($ts) {
                return $ts;
            }
        }

        return null;
    }

    /**
     * @param int $day
     * @param int $month
     * @param int $year
     * @return bool
     * @throws AppException
     */
    public function setDob(int $day, int $month, int $year): bool
    {
        if (!checkdate($month, $day, $year)) {
            throw new AppException('Invalid date of birth');
        }

        if ($year < 1900) {
            throw new AppException('DOB out of range');
        }

        $dobTs = mktime(0, 0, 0, $month, $day, $year);
        if ($dobTs >= time()) {
            throw new AppException('Cannot set a date of birth from future');
        }

        $currentDob = $this->private("dob");
        $newDob = date("dmY", $dobTs);
        if ($currentDob !== $newDob) {
            $this->set("dob", $newDob);
            return true;
        }

        return false;
    }

    /**
     * @return void
     * @throws \Comely\Cache\Exception\CacheException
     */
    public function deleteCached(): void
    {
        $this->aK->cache->delete(sprintf("u_prf_%d", $this->userId));
    }
}
