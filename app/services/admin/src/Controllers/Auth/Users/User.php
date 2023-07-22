<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth\Users;

use App\Common\Database\Primary\Countries;
use App\Common\Database\Primary\Users;
use App\Common\Exception\AppException;
use App\Common\Exception\AppModelNotFoundException;
use App\Common\Users\Credentials;
use App\Common\Users\UserParams;
use App\Common\Users\UserTagsInterface;
use App\Common\Validator;
use App\Services\Admin\Controllers\Auth\AuthAdminAPIController;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Cache\Exception\CacheException;
use Comely\Database\Exception\ORM_ModelNotFoundException;
use Comely\Database\Schema;
use Comely\Utils\Validator\Exception\ValidatorException;

/**
 * Class User
 * @package App\Services\Admin\Controllers\Auth\Users
 */
class User extends AuthAdminAPIController
{
    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function authCallback(): void
    {
        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Users\Groups');
        Schema::Bind($db, 'App\Common\Database\Primary\Users');
        Schema::Bind($db, 'App\Common\Database\Primary\Countries');

        $privileges = $this->admin->privileges();
        if (!$privileges->isRoot() && !$privileges->manageUsers) {
            throw new AdminAPIException('You are not privileged for user management');
        }
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws AppModelNotFoundException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    public function put(): void
    {
        // Validators
        $usernameValidator = Validator::Username(6, 16);
        $emailValidator = Validator::EmailAddress(64);

        // Group
        try {
            $groupId = $this->input()->getInt("groupId", unSigned: true);
            if (!($groupId > 0)) {
                throw new AdminAPIException('Select a group for new user');
            }

            try {
                $group = Users\Groups::get($groupId, useCache: true);
            } catch (AppModelNotFoundException) {
                throw new AdminAPIException('No such group exists');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("groupId");
            throw $e;
        }

        // Username
        try {
            try {
                $username = $usernameValidator->getValidated(trim($this->input()->getASCII("username")));
            } catch (ValidatorException $e) {
                $errMsg = match ($e->getCode()) {
                    \Comely\Utils\Validator\Validator::ASCII_PRINTABLE_ERROR,
                    \Comely\Utils\Validator\Validator::ASCII_CHARSET_ERROR => 'Username contains an illegal character',
                    \Comely\Utils\Validator\Validator::LENGTH_UNDERFLOW_ERROR => 'Username must must be minimum 6 characters long',
                    \Comely\Utils\Validator\Validator::LENGTH_OVERFLOW_ERROR => 'Username cannot exceed 16 characters',
                    default => 'Invalid username',
                };

                throw new AdminAPIException($errMsg, $e->getCode());
            }

            try {
                $dupUsername = Users::Find()->query('WHERE `username`=?', [$username])->first();
            } catch (ORM_ModelNotFoundException) {
            }

            if (isset($dupUsername)) {
                throw new AdminAPIException('This username is already registered');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("username");
            throw $e;
        }

        // Email Address
        try {
            try {
                $email = $emailValidator->getNullable(trim($this->input()->getASCII("email")));
            } catch (ValidatorException $e) {
                throw new AdminAPIException('Invalid e-mail address', $e->getCode());
            }

            if ($email) {
                try {
                    $dupEmail = Users::Find()->query('WHERE `email`=?', [$email])->first();
                } catch (ORM_ModelNotFoundException) {
                }

                if (isset($dupEmail)) {
                    throw new AdminAPIException('This e-mail address is already registered');
                }
            }
        } catch (AdminAPIException $e) {
            $e->setParam("email");
            throw $e;
        }

        // Phone
        try {
            $phone = trim($this->input()->getASCII("phone"));
            if ($phone) {
                if (!Validator::isValidPhone($phone)) {
                    throw new AdminAPIException('Invalid phone number');
                }
            } else {
                $phone = null;
            }

            if ($phone) {
                try {
                    $dupPhone = Users::Find()->query('WHERE `phone`=?', [$phone])->first();
                } catch (ORM_ModelNotFoundException) {
                }

                if (isset($dupPhone)) {
                    throw new AdminAPIException('This phone number is already registered');
                }
            }
        } catch (AdminAPIException $e) {
            $e->setParam("phone");
            throw $e;
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user = new \App\Common\Users\User();
            $user->id = 0;
            $user->set("checksum", "tba");
            $user->referrerId = null;
            $user->set("tags", null);
            $user->groupId = $group->id;
            $user->archived = 0;
            $user->status = "disabled";
            $user->username = $username;
            $user->email = $email;
            $user->emailVerified = 0;
            $user->phone = $phone;
            $user->phoneVerified = 0;
            $user->country = null;
            $user->set("credentials", "tba");
            $user->set("params", "tba");
            $user->createdOn = time();
            $user->updatedOn = time();

            $user->query()->insert();
            $user->id = $db->lastInsertId();
            $user->set("checksum", $user->checksum()->raw());
            $user->set("credentials", $user->cipher()->encrypt((new Credentials($user)))->raw());
            $user->set("params", $user->cipher()->encrypt((new UserParams($user)))->raw());
            $user->query()->where("id", $user->id)->update();

            $this->adminLogEntry(
                sprintf('User account %d with username "%s" created', $user->id, $user->username),
                flags: ["users", "user-account", "user-create", "user:" . $user->id]
            );
            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->status(true);
        $this->response->set("id", $user->id);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws \Exception
     */
    public function post(): void
    {
        $action = trim(strtolower($this->input()->getASCII("action")));
        switch ($action) {
            case "account":
                $this->editAccount();
                return;
            case "password":
                $this->changePassword();
                return;
            case "disable2fa":
                $this->disable2fa();
                return;
            case "checksum":
                $this->recomputeChecksum();
                return;
            case "re_credentials":
                $this->rebuildCredentials();
                return;
            case "re_params":
                $this->rebuildParams();
                return;
            case "delete":
                $this->deleteUser();
                return;
            case "restore":
                $this->restoreDeletedUser();
                return;
            case "referrer":
                $this->changeReferrer();
                return;
            case "verifications":
                $this->updateVerifications();
                return;
            case "flags":
            case "tags":
                $this->updateTags();
                return;
            case "params":
                $this->updateParams();
                return;
            default:
                throw AdminAPIException::Param("action", "Invalid action called for user account");
        }
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function updateTags(): void
    {
        $user = $this->fetchUserObject(true);
        $currentTagsStr = $user->private("tags") ?? "";
        $tags = explode(",", strtolower(trim($this->input()->getASCII("tags"))));
        $user->clearTags();

        if ($tags) {
            foreach ($tags as $tag) {
                if (!$tag) {
                    continue;
                }

                if (!preg_match('/^\w{4,32}$/', $tag)) {
                    throw new AdminAPIException('Invalid user tag');
                }

                $user->appendTag($tag);
            }
        }

        $user->updateUserTagsInternal();
        if ($currentTagsStr === $user->private("tags")) {
            throw new AdminAPIException('There are no changes to be saved');
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw());
            $user->query()->update();

            $this->adminLogEntry(
                sprintf('User "%s" internal flags updated', $user->username),
                flags: ["users", "user-account", "user:" . $user->id]
            );

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);

        $this->status(true);
        $this->response->set("tags", $user->tags());
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Security\Exception\CipherException
     */
    private function updateParams(): void
    {
        $changes = 0;
        $user = $this->fetchUserObject(true);
        $userParams = $user->params();

        // Secure data
        // This is an example/dummy field
        $secureData = $this->input()->getASCII("secureData");
        if ($secureData) {
            $secureDataLen = strlen($secureData);
            if ($secureDataLen < 3 || $secureDataLen > 128) {
                throw AdminAPIException::Param("secureData", "Invalid secure data");
            }

            $changes += (int)$userParams->setSecureData($secureData);
        } else {
            $changes += (int)$userParams->setSecureData(null);
        }

        // Changes?
        if (!$changes) {
            throw new AdminAPIException('There are no changes to saved!');
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->updatedOn = time();
            $user->set("params", $user->cipher()->encrypt($userParams)->raw());
            $user->query()->update();

            $this->adminLogEntry(
                sprintf('User "%s" encrypted params updated', $user->username),
                flags: ["users", "user-account", "user:" . $user->id]
            );

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws AppModelNotFoundException
     * @throws ValidatorException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function editAccount(): void
    {
        $user = $this->fetchUserObject(true);
        $changes = 0;

        // Validators
        $usernameValidator = Validator::Username();
        $emailValidator = Validator::EmailAddress();

        // Group
        try {
            $group = Users\Groups::get($this->input()->getInt("groupId", unSigned: true), true);
        } catch (AppModelNotFoundException) {
            throw AdminAPIException::Param("groupId", "Select a users group");
        }

        if ($group->id !== $user->groupId) {
            $changes++;
        }

        // Status
        $status = strtolower(trim($this->input()->getASCII("status")));
        if (!in_array($status, ["active", "disabled"])) {
            throw AdminAPIException::Param("status", "Invalid user account status");
        }

        if ($status !== $user->status) {
            $oldStatus = $user->status;
            $user->status = $status;
            $changes++;
        }

        // Username
        try {
            $username = $usernameValidator->getValidated($this->input()->getASCII("username"));
        } catch (ValidatorException $e) {
            $errStr = match ($e->getCode()) {
                \Comely\Utils\Validator\Validator::LENGTH_UNDERFLOW_ERROR => 'Username must be 6 characters long',
                \Comely\Utils\Validator\Validator::LENGTH_OVERFLOW_ERROR => 'Username cannot exceed 16 characters',
                \Comely\Utils\Validator\Validator::REGEX_MATCH_ERROR => 'Username contains illegal character',
                default => 'Invalid username',
            };

            throw AdminAPIException::Param("username", $errStr, $e->getCode());
        }

        if (strtolower($username) !== strtolower($user->username)) {
            // Duplicate check
            try {
                $dupUsername = Users::Find()->query('WHERE `username`=?', [$username])->first();
            } catch (ORM_ModelNotFoundException) {
            }

            if (isset($dupUsername)) {
                throw AdminAPIException::Param("username", "This username is already registered");
            }

            $oldUsername = $user->username;
            $user->username = $username;
            $changes++;
        }

        // E-mail Address
        try {
            $email = $emailValidator->getNullable($this->input()->getASCII("email"));
        } catch (ValidatorException $e) {
            throw AdminAPIException::Param("email", "Invalid e-mail address", $e->getCode());
        }

        if ($email !== $user->email) {
            if ($email) {
                // Duplicate check
                try {
                    $dupEmail = Users::Find()->query('WHERE `email`=?', [$email])->first();
                } catch (ORM_ModelNotFoundException) {
                }

                if (isset($dupEmail)) {
                    throw AdminAPIException::Param("email", "This e-mail address is already registered");
                }

                $oldEmail = $user->email ?: "NULL";
                $user->email = $email;
            } else {
                $user->email = null;
            }

            $user->emailVerified = 0;
            $changes++;
        }

        // Phone
        $phone = trim($this->input()->getASCII("phone"));
        if ($phone) {
            if (!Validator::isValidPhone($phone)) {
                throw AdminAPIException::Param("phone", "Invalid phone number");
            }
        } else {
            $phone = null;
        }

        if ($phone !== $user->phone) {
            if ($phone) {
                // Duplicate check
                try {
                    $dupPhone = Users::Find()->query('WHERE `phone`=?', [$phone])->first();
                } catch (ORM_ModelNotFoundException) {
                }

                if (isset($dupPhone)) {
                    throw AdminAPIException::Param("phone", "This phone number is already registered");
                }

                $oldPhone = $user->phone ?: "NULL";
                $user->phone = $phone;
            } else {
                $user->phone = null;
            }

            $user->phoneVerified = 0;
            $changes++;
        }

        // Country
        $country = trim($this->input()->getASCII("country"));
        if ($country) {
            if (strlen($country) !== 3) {
                throw new AdminAPIException('Invalid selected country');
            }

            $country = Countries::Get($country, true);
        } else {
            $country = null;
        }

        if (is_null($country) && $user->country) {
            $user->country = null;
            $changes++;
        }

        if ($country) {
            if ($user->country !== $country->code) {
                $user->country = $country->code;
                $changes++;
            }
        }

        // Changes
        if (!($changes > 0)) {
            throw new AdminAPIException('There are no changes to be saved');
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        // Admin Logs
        $adminLogs = [];
        if (isset($oldUsername)) {
            $adminLogs[] = sprintf('User %d username changed from "%s" to "%s"', $user->id, $oldUsername, $user->username);
        }

        if (isset($oldStatus)) {
            $adminLogs[] = sprintf('User "%s" status changed from %s to %s', $user->username, strtoupper($oldStatus), strtoupper($user->status));
        }

        if (isset($oldEmail)) {
            $adminLogs[] = sprintf('User "%s" e-mail address changed from %s to %s', $user->username, $oldEmail, $user->email);
        }

        if (isset($oldPhone)) {
            $adminLogs[] = sprintf('User "%s" phone no. changed from %s to %s', $user->username, $oldPhone, $user->phone);
        }

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw());
            $user->query()->update();

            if (!$adminLogs) {
                $adminLogs[] = sprintf('User "%s" account updated', $user->username);
            }

            foreach ($adminLogs as $adminLog) {
                $this->adminLogEntry($adminLog, flags: ["users", "user-account", "user-edit", "user:" . $user->id]);
            }

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
        $this->response->set("user", $user);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws AppModelNotFoundException
     * @throws \Comely\Database\Exception\DbConnectionException
     * @throws \Comely\Database\Exception\PDO_Exception
     */
    private function changeReferrer(): void
    {
        $user = $this->fetchUserObject(true);

        $referrerUsername = trim($this->input()->getASCII("referrer"));
        if ($referrerUsername) {
            try {
                if (!Validator::isValidUsername($referrerUsername)) {
                    throw new AdminAPIException('Invalid referrer username');
                }
                try {
                    $referrer = Users::Get(username: $referrerUsername, useCache: true);
                } catch (AppModelNotFoundException) {
                    throw new AdminAPIException('No such referrer account exists');
                }

                if ($user->referrerId === $referrer->id) {
                    throw new AdminAPIException('There are no changes to be saved');
                }

                if ($referrer->id === $user->id) {
                    throw new AdminAPIException('Cannot be own referrer');
                }

                $user->referrerId = $referrer->id;
            } catch (AdminAPIException $e) {
                $e->setParam("referrer");
                throw $e;
            }
        } else {
            if (!$user->referrerId) {
                throw AdminAPIException::Param("referrer", "There are no changes to be saved");
            }

            $user->referrerId = null;
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw());
            $user->query()->update();

            $this->adminLogEntry(
                sprintf('User "%s" referrer changed to "%s"', $user->username, isset($referrer) ? $referrer->username : "NULL"),
                flags: ["users", "user-account", "user:" . $user->id]
            );

            $db->commit();
        } catch (\Exception $e) {
            $db->error();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
        $this->response->set("referrer", isset($referrer) ? $referrer->username : null);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function updateVerifications(): void
    {
        $user = $this->fetchUserObject(true);
        $changes = 0;
        $adminLogs = [];

        // E-mail verification
        $emailVerified = Validator::getBool(trim($this->input()->getASCII("emailVerified")));
        if ($emailVerified !== (bool)$user->emailVerified) {
            if ($emailVerified && !$user->email) {
                throw new AdminAPIException('This account does not have an e-mail address set');
            }

            $user->emailVerified = $emailVerified ? 1 : 0;
            $adminLogs[] = sprintf('User "%s" e-mail address "%s" marked as %s', $user->username, $user->email, $emailVerified ? "VERIFIED" : "UNVERIFIED");
            $changes++;
        }

        // Phone verification
        $phoneVerified = Validator::getBool(trim($this->input()->getASCII("phoneVerified")));
        if ($phoneVerified !== (bool)$user->phoneVerified) {
            if ($emailVerified && !$user->phone) {
                throw new AdminAPIException('This account does not have a phone no. set');
            }

            $user->phoneVerified = $phoneVerified ? 1 : 0;
            $adminLogs[] = sprintf('User "%s" phone no. "%s" marked as %s', $user->username, $user->phone, $phoneVerified ? "VERIFIED" : "UNVERIFIED");
            $changes++;
        }

        // Changes
        if (!($changes > 0)) {
            throw new AdminAPIException('There are no changes to be saved');
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw());
            $user->query()->update();

            foreach ($adminLogs as $adminLog) {
                $this->adminLogEntry($adminLog, flags: ["users", "user-account", "user:" . $user->id]);
            }

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws ValidatorException
     * @throws \Comely\Database\Exception\DbConnectionException
     * @throws \Comely\Database\Exception\PDO_Exception
     */
    private function changePassword(): void
    {
        $user = $this->fetchUserObject(true);
        $credentials = $user->credentials();
        $passwordValidator = Validator::Password(minStrength: 3);

        // New temporary password
        try {
            $tempPassword = $passwordValidator->getValidated(trim($this->input()->getASCII("password")));
        } catch (ValidatorException $e) {
            $errMsg = match ($e->getCode()) {
                \Comely\Utils\Validator\Validator::ASCII_CHARSET_ERROR,
                \Comely\Utils\Validator\Validator::ASCII_PRINTABLE_ERROR => 'Password contains an illegal character',
                \Comely\Utils\Validator\Validator::LENGTH_UNDERFLOW_ERROR => 'Password must be 8 characters long',
                \Comely\Utils\Validator\Validator::LENGTH_OVERFLOW_ERROR => 'Password cannot exceed 32 characters',
                \Comely\Utils\Validator\Validator::CALLBACK_TYPE_ERROR => 'Password is not strong enough',
                default => 'Invalid password'
            };

            throw AdminAPIException::Param("password", $errMsg);
        }

        // Already same password?
        if ($credentials->verifyPassword($tempPassword)) {
            throw new AdminAPIException('There are no changes to be saved');
        }

        // Add the tag?
        try {
            $addFlag = trim($this->input()->getASCII("flag"));
            if ($addFlag) {
                if (!in_array($addFlag, [UserTagsInterface::SUGGEST_PASSWORD_CHANGE, UserTagsInterface::FORCE_PASSWORD_CHANGE])) {
                    throw new AdminAPIException('Cannot add irrelevant flag with password change');
                }

                $user->appendTag($addFlag);
                $user->updateUserTagsInternal();
            }
        } catch (AdminAPIException $e) {
            $e->setParam("flag");
            throw $e;
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $credentials->changePassword($tempPassword);
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw()); // Because of possible flags append
            $user->set("credentials", $user->cipher()->encrypt($credentials)->raw());
            $user->query()->update();

            $this->adminLogEntry(
                sprintf('User "%s" password changed', $user->username),
                flags: ["users", "user-account", "user:" . $user->id]
            );

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Security\Exception\CipherException
     */
    private function disable2fa(): void
    {
        $user = $this->fetchUserObject(true);

        $credentials = $user->credentials();
        if (!$credentials->getGoogleAuthSeed()) {
            throw AdminAPIException::Param("action", "Google Auth is already disabled for this account");
        }

        $credentials->changeGoogleAuthSeed(null);

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $successLog = sprintf('User "%s" 2FA disabled', $user->username);

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->updatedOn = time();
            $user->set("credentials", $user->cipher()->encrypt($credentials)->raw());
            $user->query()->update();

            $this->adminLogEntry($successLog, flags: ["users", "user-account", "user:" . $user->id]);

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
        $this->response->set("success", $successLog);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function recomputeChecksum(): void
    {
        $user = $this->fetchUserObject(false);
        if ($user->_checksumValidated) {
            throw AdminAPIException::Param("action", "Checksum for this user is already OK");
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $successLog = sprintf('User "%s" checksum recomputed', $user->username);

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw());
            $user->query()->update();

            $this->adminLogEntry($successLog, flags: ["users", "user-account", "user:" . $user->id]);

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
        $this->response->set("success", $successLog);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Security\Exception\CipherException
     */
    private function rebuildCredentials(): void
    {
        $user = $this->fetchUserObject(true);

        try {
            $credentials = $user->credentials();
        } catch (AppException) {
        }

        if (isset($credentials)) {
            throw AdminAPIException::Param("action", "User credentials object already OK");
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $successLog = sprintf('User "%s" credentials rebuilt', $user->username);

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $credentials = new Credentials($user);
            $user->updatedOn = time();
            $user->set("credentials", $user->cipher()->encrypt($credentials)->raw());
            $user->query()->update();

            $this->adminLogEntry($successLog, flags: ["users", "user-account", "user:" . $user->id]);

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
        $this->response->set("success", $successLog);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Security\Exception\CipherException
     */
    private function rebuildParams(): void
    {
        $user = $this->fetchUserObject(true);

        try {
            $params = $user->params();
        } catch (AppException) {
        }

        if (isset($params)) {
            throw AdminAPIException::Param("action", "User encrypted params object already OK");
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $successLog = sprintf('User "%s" encrypted params rebuilt', $user->username);

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $params = new UserParams($user);
            $user->updatedOn = time();
            $user->set("params", $user->cipher()->encrypt($params)->raw());
            $user->query()->update();

            $this->adminLogEntry($successLog, flags: ["users", "user-account", "user:" . $user->id]);

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
        $this->response->set("success", $successLog);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function deleteUser(): void
    {
        $user = $this->fetchUserObject(true);
        if ($user->archived === 1) {
            throw new AdminAPIException('This user account is already deleted');
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->archived = 1;
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw());
            $user->query()->update();

            $this->adminLogEntry(
                sprintf('User "%s" marked as archived', $user->username),
                flags: ["users", "user-account", "user:" . $user->id]
            );

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function restoreDeletedUser(): void
    {
        $user = $this->fetchUserObject(true);
        if ($user->archived === 0) {
            throw new AdminAPIException('This user account is already active');
        }

        // Verify TOTP
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $user->archived = 0;
            $user->updatedOn = time();
            $user->set("checksum", $user->checksum()->raw());
            $user->query()->update();

            $this->adminLogEntry(
                sprintf('User "%s" restored from archived', $user->username),
                flags: ["users", "user-account", "user:" . $user->id]
            );

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->afterUserIsUpdated($user);
        $this->status(true);
    }

    /**
     * @return void
     * @throws AdminAPIException
     */
    public function get(): void
    {
        $user = $this->fetchUserObject();
        $errors = [];

        // Params
        try {
            $params = $user->params();
        } catch (AppException $e) {
            $errors[] = $e->getMessage();
        }

        if (isset($params)) {
            $userParams = $params->getPublicArray();
        }

        // Referrer
        try {
            $user->referrerUsername = $user->referrerId ? Users::CachedUsername($user->referrerId) : null;
        } catch (AppException $e) {
            $errors[] = $e->getMessage();
            $errors[] = "Failed to retrieve referrer username";
        }

        // Referrals Counts
        try {
            $user->getReferralsCount();
        } catch (AppException $e) {
            $user->referralsCount = -1;
            $errors[] = $e->getMessage();
        }

        $this->status(true);
        $this->response->set("user", $user);
        $this->response->set("tags", $user->tags());
        $this->response->set("params", $userParams ?? []);
        $this->response->set("errors", $errors);
        $this->response->set("knownUsersFlags", UserTagsInterface::KNOWN_FLAGS);
    }

    /**
     * @param \App\Common\Users\User $user
     * @return void
     */
    private function afterUserIsUpdated(\App\Common\Users\User $user): void
    {
        try {
            $user->deleteCached(false);
        } catch (CacheException $e) {
            $this->aK->errors->trigger($e, E_USER_WARNING);
        }
    }

    /**
     * @param bool $validateChecksum
     * @return \App\Common\Users\User
     * @throws AdminAPIException
     */
    private function fetchUserObject(bool $validateChecksum = false): \App\Common\Users\User
    {
        try {
            $userId = $this->input()->getInt("user", unSigned: true) ?? -1;
            if (!($userId > 0)) {
                throw new AdminAPIException('Invalid "user" param');
            }

            $user = Users::Get(id: $userId, useCache: false);
            try {
                $user->validateChecksum();
            } catch (AppException) {
                if ($validateChecksum) {
                    throw new AdminAPIException(sprintf('User %d checksum does not validate', $user->id));
                }
            }

            return $user;
        } catch (AdminAPIException $e) {
            $e->setParam("user");
            throw $e;
        } catch (AppException $e) {
            throw AdminAPIException::Param("user", $e->getMessage(), $e->getCode());
        }
    }
}
