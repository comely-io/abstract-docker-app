<?php
declare(strict_types=1);

namespace App\Common\Users;

use App\Common\Database\AbstractAppModel;
use App\Common\Database\Primary\Users;
use App\Common\Exception\AppException;
use App\Common\Kernel\ErrorHandler\Errors;
use App\Common\PublicAPI\Session;
use App\Common\Security;
use App\Common\Validator;
use Comely\Buffer\Buffer;
use Comely\Cache\Exception\CacheException;
use Comely\Security\Cipher;
use Comely\Security\Exception\CipherException;

/**
 * Class User
 * @package App\Common\Users
 * @property string|null $referrerUsername
 * @property int|null $referralsCount
 * @property bool|null $checksumVerified
 */
class User extends AbstractAppModel
{
    public const TABLE = Users::TABLE;
    public const SERIALIZABLE = true;

    /** @var int */
    public int $id;
    /** @var int|null */
    public ?int $referrerId = null;
    /** @var int */
    public int $groupId;
    /** @var int */
    public int $archived;
    /** @var string */
    public string $status;
    /** @var string */
    public string $username;
    /** @var string|null */
    public ?string $email = null;
    /** @var int */
    public int $emailVerified = 0;
    /** @var string|null */
    public ?string $phone = null;
    /** @var int */
    public int $phoneVerified = 0;
    /** @var string|null */
    public ?string $country = null;
    /** @var int */
    public int $createdOn;
    /** @var int */
    public int $updatedOn;

    /** @var Cipher|null */
    private ?Cipher $_cipher = null;
    /** @var bool|null */
    private ?bool $_checksumValidated = null;
    /** @var array */
    private array $_tags = [];
    /** @var Credentials|null */
    private ?Credentials $_credentials = null;
    /** @var UserParams|null */
    private ?UserParams $_params = null;
    /** @var UserBaggage|null */
    private ?UserBaggage $_baggage = null;

    /**
     * @return void
     */
    public function onLoad(): void
    {
        $this->_tags = explode(",", trim(trim($this->private("tags") ?? ""), ","));
        parent::onLoad();

        try {
            $this->aK->cache->set(sprintf("u_username_%d", $this->id), $this->username);
        } catch (CacheException $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            $this->aK->errors->trigger('Failed to store loaded username is cache', E_USER_WARNING);
        }
    }

    /**
     * @return void
     */
    public function onUnserialize(): void
    {
        $this->_tags = explode(",", trim(trim($this->private("tags") ?? ""), ","));
        parent::onUnserialize();
    }

    /**
     * @return void
     */
    public function onSerialize(): void
    {
        $this->_cipher = null;
        $this->_checksumValidated = false;
        $this->_credentials = null;
        $this->_params = null;
        $this->_tags = [];
        $this->_baggage = null;
        parent::onSerialize();
    }

    /**
     * @return void
     */
    public function beforeQuery(): void
    {
        // Booleans correction
        $this->archived = $this->archived === 1 ? 1 : 0;
        $this->emailVerified = $this->emailVerified === 1 ? 1 : 0;
        $this->phoneVerified = $this->phoneVerified === 1 ? 1 : 0;
    }

    /**
     * @return Buffer
     * @throws AppException
     */
    public function checksum(): Buffer
    {
        $this->updateUserTagsInternal(); // Update tags associated with user account
        $raw = sprintf(
            "%d:%d:%d:%s:%d:%s:%s:%s:%d:%s:%d:%s:%d",
            $this->id,
            $this->referrerId > 0 ? $this->referrerId : 0,
            $this->groupId,
            $this->private("tags"),
            $this->archived === 1 ? 1 : 0,
            trim(strtolower($this->status)),
            trim(strtolower($this->username)),
            trim(strtolower($this->email ?? "")),
            $this->emailVerified === 1 ? 1 : 0,
            trim(strtolower($this->phone ?? "")),
            $this->phoneVerified === 1 ? 1 : 0,
            strtolower($this->country ?? ""),
            $this->createdOn
        );

        try {
            return $this->cipher()->pbkdf2("sha1", $raw, Security::PBKDF2_Iterations($this->id, static::TABLE));
        } catch (CipherException $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AppException(sprintf('Failed to compute user %d checksum', $this->id));
        }
    }

    /**
     * @return void
     * @throws AppException
     */
    public function validateChecksum(): void
    {
        if ($this->checksum()->raw() !== $this->private("checksum")) {
            throw new AppException(sprintf('User %d checksum validation failed', $this->id));
        }

        $this->_checksumValidated = true;
    }

    /**
     * @return bool
     */
    public function isChecksumValidated(): bool
    {
        return (bool)$this->_checksumValidated;
    }

    /**
     * @return array
     */
    public function tags(): array
    {
        return $this->_tags;
    }

    /**
     * @return void
     */
    public function clearTags(): void
    {
        $this->_tags = [];
    }

    /**
     * @param string $tag
     * @return bool
     */
    public function hasTag(string $tag): bool
    {
        return in_array(strtolower(trim($tag)), $this->_tags);
    }

    /**
     * @param string $tag
     * @return bool
     */
    public function deleteTag(string $tag): bool
    {
        $index = array_search(strtolower(trim($tag)), $this->_tags);
        if (is_int($index) && $index >= 0) {
            unset($this->_tags[$index]);
            return true;
        }

        return false;
    }

    /**
     * @param string $tag
     * @return bool
     */
    public function appendTag(string $tag): bool
    {
        $tag = strtoupper(trim($tag));
        if (!$this->hasTag($tag)) {
            $this->_tags[] = $tag;
            return true;
        }

        return false;
    }

    /**
     * @return void
     */
    public function updateUserTagsInternal(): void
    {
        $tagsStr = implode(",", array_unique($this->_tags));
        if (strlen($tagsStr) > 512) {
            throw new \RuntimeException(sprintf('User %d account tags exceeding limit of 512 bytes', $this->id));
        }

        $this->set("tags", trim($tagsStr, ","));
    }

    /**
     * @return Credentials
     * @throws AppException
     */
    public function credentials(): Credentials
    {
        if ($this->_credentials) {
            return $this->_credentials;
        }

        try {
            $credentials = $this->cipher()->decrypt($this->private("credentials"));
            if (!$credentials instanceof Credentials) {
                throw new AppException(
                    sprintf('Unexpected result of type "%s" while decrypting user %d credentials', Validator::getType($credentials), $this->id)
                );
            }

            if ($credentials->userId !== $this->id) {
                throw new AppException(
                    sprintf('Credentials user id %d mismatches with loaded user %d', $credentials->userId, $this->id)
                );
            }
        } catch (\Exception $e) {
            if ($e instanceof AppException) {
                throw $e;
            }

            if ($this->aK->isDebug()) {
                trigger_error(Errors::Exception2String($e), E_USER_WARNING);
            }

            throw new AppException(sprintf('Failed to decrypt user %d credentials', $this->id));
        }

        $this->_credentials = $credentials;
        return $this->_credentials;
    }

    /**
     * @return UserParams
     * @throws AppException
     */
    public function params(): UserParams
    {
        if ($this->_params) {
            return $this->_params;
        }

        try {
            $params = $this->cipher()->decrypt($this->private("params"));
            if (!$params instanceof UserParams) {
                throw new AppException(
                    sprintf('Unexpected result of type "%s" while decrypting user %d params', Validator::getType($params), $this->id)
                );
            }

            if ($params->userId !== $this->id) {
                throw new AppException(
                    sprintf('UserParams object user id %d mismatches with loaded user %d', $params->userId, $this->id)
                );
            }
        } catch (\Exception $e) {
            if ($e instanceof AppException) {
                throw $e;
            }

            if ($this->aK->isDebug()) {
                trigger_error(Errors::Exception2String($e), E_USER_WARNING);
            }

            throw new AppException(sprintf('Failed to decrypt user %d params', $this->id));
        }

        $this->_params = $params;
        return $this->_params;
    }

    /**
     * @return UserBaggage
     */
    public function baggage(): UserBaggage
    {
        if ($this->_baggage) {
            return $this->_baggage;
        }

        $this->_baggage = new UserBaggage($this);
        return $this->_baggage;
    }

    /**
     * @return Cipher
     * @throws AppException
     */
    public function cipher(): Cipher
    {
        if ($this->_cipher) {
            return $this->_cipher;
        }

        try {
            $this->_cipher = $this->aK->ciphers->primary()->remixChild(sprintf("user_%d", $this->id));
        } catch (\Exception $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AppException(sprintf('Cannot retrieve user %d cipher', $this->id));
        }

        return $this->_cipher;
    }

    /**
     * @return int
     * @throws AppException
     */
    public function getReferralsCount(): int
    {
        try {
            $db = $this->aK->db->primary();
            $query = $db->fetch(sprintf('SELECT ' . 'count(*) FROM `%s` WHERE `referrer_id`=?', Users::TABLE), [$this->id]);
            $count = $query->row();

            if (!isset($count["count(*)"])) {
                throw new \RuntimeException();
            }

            $this->referralsCount = intval($count["count(*)"]);
            return $this->referralsCount;
        } catch (\Exception $e) {
            if (!$e instanceof \RuntimeException) {
                $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            }

            throw new AppException(sprintf('Failed to retrieve user "%s" referrals count', $this->username));
        }
    }

    /**
     * @param bool $deleteRelevantObjects
     * @return void
     * @throws \Comely\Cache\Exception\CacheException
     */
    public function deleteCached(bool $deleteRelevantObjects = true): void
    {
        $cache = $this->aK->cache;
        $cache->delete(sprintf("user_%d", $this->id));
        $cache->delete(sprintf("user_u_%s", strtolower(trim($this->username))));

        if ($this->email) {
            $cache->delete(sprintf("user_em_%s", md5(strtolower(trim($this->email)))));
        }

        if ($this->phone) {
            $cache->delete(sprintf("user_ph_%s", md5(strtolower(trim($this->phone)))));
        }

        // Username
        $cache->delete(sprintf("u_username_%d", $this->id));

        if ($deleteRelevantObjects) {
            // Profile
            $cache->delete(sprintf("u_prf_%d", $this->id));
        }
    }

    /**
     * @param Session $session
     * @param string $hmacSecret
     * @return void
     */
    public function authenticateSession(Session $session, string $hmacSecret): void
    {
        if ($session->authUserId !== $this->id) {
            throw new \RuntimeException('Authenticate session model with user model first');
        }

        if (strlen($hmacSecret) !== 16) {
            throw new \RuntimeException('HMAC secret for session must be 16 bytes');
        }

        $this->set($session->type . "AuthToken", $session->private("token") . $hmacSecret);
    }
}
