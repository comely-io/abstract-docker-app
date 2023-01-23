<?php
declare(strict_types=1);

namespace App\Common\Database\Primary;

use App\Common\AppKernel;
use App\Common\Database\AbstractAppTable;
use App\Common\Database\Primary\Users\Groups;
use App\Common\Exception\AppException;
use App\Common\Exception\AppModelNotFoundException;
use App\Common\Users\User;
use App\Common\Validator;
use Comely\Cache\Exception\CacheException;
use Comely\Database\Exception\DatabaseException;
use Comely\Database\Exception\ORM_ModelNotFoundException;
use Comely\Database\Schema\Table\Columns;
use Comely\Database\Schema\Table\Constraints;

/**
 * Class Users
 * @package App\Common\Database\Primary
 */
class Users extends AbstractAppTable
{
    public const TABLE = "users";
    public const ORM_CLASS = 'App\Common\Users\User';
    public const CACHE_TTL = 86400;

    /**
     * @param Columns $cols
     * @param Constraints $constraints
     * @return void
     */
    public function structure(Columns $cols, Constraints $constraints): void
    {
        $cols->defaults("ascii", "ascii_general_ci");

        $cols->int("id")->bytes(4)->unSigned()->autoIncrement();
        $cols->binary("checksum")->fixed(20);
        $cols->int("referrer_id")->bytes(4)->unSigned()->nullable();
        $cols->string("tags")->length(512)->nullable();
        $cols->int("group_id")->bytes(4)->unSigned();
        $cols->int("archived")->bytes(1)->default(0);
        $cols->enum("status")->options("active", "disabled")->default("active");
        $cols->string("username")->length(16)->unique();
        $cols->string("email")->length(64)->nullable()->unique();
        $cols->int("email_verified")->bytes(1)->default(0);
        $cols->string("phone")->length(32)->nullable()->unique();
        $cols->int("phone_verified")->bytes(1)->default(0);
        $cols->string("country")->fixed(3)->nullable();
        $cols->binary("credentials")->length(4096); // 4 KB encrypted credentials object
        $cols->binary("params")->length(6144); // 6 KB encrypted params object
        $cols->binary("web_auth_token")->fixed(48)->nullable(); // 32 bytes session ID + 16 bytes hmac secret
        $cols->binary("app_auth_token")->fixed(48)->nullable(); // 32 bytes session ID + 16 bytes hmac secret
        $cols->int("created_on")->bytes(4)->unSigned();
        $cols->int("updated_on")->bytes(4)->unSigned();
        $cols->primaryKey("id");

        $constraints->foreignKey("referrer_id")->table(static::TABLE, "id");
        $constraints->foreignKey("group_id")->table(Groups::TABLE, "id");
        $constraints->foreignKey("country")->table(Countries::TABLE, "code");
    }

    /**
     * @param int|null $id
     * @param string|null $username
     * @param string|null $email
     * @param string|null $phone
     * @param bool $useCache
     * @return User
     * @throws AppException
     * @throws AppModelNotFoundException
     */
    public static function Get(?int $id = 0, ?string $username = null, ?string $email = null, ?string $phone = null, bool $useCache = true): User
    {
        $aK = AppKernel::getInstance();

        if ($id > 0) {
            $instanceId = sprintf("user_%d", $id);
            $search = ["id", $id];
        } elseif ($username) {
            $instanceId = sprintf("user_u_%s", strtolower(trim($username)));
            $search = ["username", $username];
        } elseif ($email) {
            $instanceId = sprintf("user_em_%s", md5(strtolower(trim($email))));
            $search = ["email", $email];
        } elseif ($phone) {
            $instanceId = sprintf("user_ph_%s", md5(strtolower(trim($phone))));
            $search = ["phone", $phone];
        }

        if (!isset($instanceId, $search)) {
            throw new \RuntimeException('No user search argument specified');
        }

        try {
            $qM = $aK->memory->query($instanceId, self::ORM_CLASS);
            if ($useCache) {
                $qM->cache(static::CACHE_TTL);
            }

            return $qM->fetch(function () use ($search) {
                return self::Find()->col($search[0], $search[1])->limit(1)->first();
            });
        } catch (\Exception $e) {
            if ($e instanceof ORM_ModelNotFoundException) {
                throw new AppModelNotFoundException('No such user account exists');
            }

            $aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AppException('Failed to retrieve user account');
        }
    }

    /**
     * @param int|string ...$userIds
     * @return array
     */
    public static function CachedUsernames(int|string ...$userIds): array
    {
        $userIds = array_unique($userIds);
        $aK = AppKernel::getInstance();
        $usernames = [];
        $searchInDb = [];

        // Check in cache first
        foreach ($userIds as $userId) {
            if ($userId <= 0) {
                continue;
            }

            // Cached Username
            try {
                $username = $aK->cache->get(sprintf("u_username_%d", $userId));
            } catch (CacheException) {
            }

            if (isset($username) && Validator::isValidUsername($username)) {
                $usernames[$userId] = $username;
                continue;
            }

            $searchInDb[] = $userId;
        }

        // Check in DB
        if (!$searchInDb) {
            return $usernames;
        }

        try {
            $users = $aK->db->primary()
                ->fetch(sprintf('SELECT ' . '`id`,`username` FROM `%s` WHERE `id` IN (%s)', Users::TABLE, implode(",", $searchInDb)))
                ->all();
        } catch (DatabaseException $e) {
            $aK->errors->triggerIfDebug($e, E_USER_WARNING);
        }

        if (isset($users) && $users) {
            foreach ($users as $user) {
                if (isset($user["id"], $user["username"]) && is_string($user["username"]) && Validator::isValidUsername($user["username"])) {
                    $userId = intval($user["id"]);
                    $username = $usernames["username"];
                    $usernames[$userId] = $username;

                    try {
                        $aK->cache->set(sprintf("u_username_%d", $userId), $username, static::CACHE_TTL * 7);
                    } catch (CacheException $e) {
                        $aK->errors->triggerIfDebug($e, E_USER_WARNING);
                        $aK->errors->trigger('Failed to store username in cache', E_USER_WARNING);
                    }
                }
            }
        }

        return $usernames;
    }

    /**
     * @param int $userId
     * @return string
     * @throws AppException
     * @throws AppModelNotFoundException
     */
    public static function CachedUsername(int $userId): string
    {
        $aK = AppKernel::getInstance();
        $cacheKey = sprintf("u_username_%d", $userId);

        try {
            $username = $aK->cache->get($cacheKey);
        } catch (CacheException) {
        }

        if (isset($username) && Validator::isValidUsername($username)) {
            return $username;
        }

        try {
            $userRow = $aK->db->primary()->query()->table(self::TABLE)
                ->cols("id", "username")
                ->where('`id`=?', [$userId])
                ->fetch()
                ->row();
        } catch (DatabaseException) {
        }

        if (!isset($userRow) || !is_array($userRow) || !isset($userRow["username"])) {
            throw new AppModelNotFoundException(sprintf('No such user account %d exists', $userId));
        }

        $username = $userRow["username"];
        if (!Validator::isValidUsername($username)) {
            throw new AppException(sprintf('User account %d has invalid username', $userId));
        }

        try {
            $aK->cache->set($cacheKey, $username, static::CACHE_TTL * 7);
        } catch (CacheException $e) {
            $aK->errors->triggerIfDebug($e, E_USER_WARNING);
            $aK->errors->trigger('Failed to store username in cache', E_USER_WARNING);
        }

        return $username;
    }
}
