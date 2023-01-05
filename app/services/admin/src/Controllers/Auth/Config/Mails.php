<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth\Config;

use App\Common\DataStore\MailConfig;
use App\Common\DataStore\MailService;
use App\Common\Exception\AppException;
use App\Common\Validator;
use App\Services\Admin\Controllers\Auth\AuthAdminAPIController;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Cache\Exception\CacheException;
use Comely\Utils\Validator\Exception\ValidatorException;

/**
 * Class Mails
 * @package App\Services\Admin\Controllers\Auth\Config
 */
class Mails extends AuthAdminAPIController
{
    /** @var MailConfig */
    private MailConfig $mailConfig;

    /**
     * @return void
     */
    protected function authCallback(): void
    {
        try {
            $this->mailConfig = MailConfig::getInstance(false);
        } catch (\Exception $e) {
            $this->aK->errors->trigger($e, E_USER_WARNING);
            $this->mailConfig = new MailConfig();
        }
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     * @throws \Comely\Database\Exception\DbConnectionException
     * @throws \Comely\Database\Exception\PDO_Exception
     */
    public function post(): void
    {
        if (!$this->admin->privileges()->isRoot()) {
            if (!$this->admin->privileges()->editConfig) {
                throw new AdminAPIException('You do not have privilege to edit configuration');
            }
        }

        $this->totpResourceLock();
        $changes = 0;

        try {
            $service = $this->input()->getASCII("service");
            if (!$service) {
                throw new AdminAPIException('Mailing service/vendor is required');
            }

            $service = MailService::tryFrom($service);
            if (!$service) {
                throw new AdminAPIException('Invalid mailing service/vendor');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("service");
            throw $e;
        }

        if ($this->mailConfig->setValue("service", $service, true)) {
            $changes++;
        }

        // Sender name and email
        $nameValidator = Validator::Name(maxLength: 32, allowDashes: true);
        $emailValidator = Validator::EmailAddress();

        try {
            if ($this->mailConfig->setValue("senderName", $nameValidator->getValidated($this->input()->getUnsafe("senderName")), true)) {
                $changes++;
            }
        } catch (ValidatorException $e) {
            $error = match ($e->getCode()) {
                \Comely\Utils\Validator\Validator::LENGTH_UNDERFLOW_ERROR => 'Sender name is too short',
                \Comely\Utils\Validator\Validator::LENGTH_OVERFLOW_ERROR => 'Sender name is too long',
                default => 'Invalid sender name'
            };

            throw AdminAPIException::Param("senderName", $error, $e->getCode());
        }

        try {
            if ($this->mailConfig->setValue("senderEmail", $emailValidator->getValidated($this->input()->getUnsafe("senderEmail")), true)) {
                $changes++;
            }
        } catch (ValidatorException $e) {
            throw AdminAPIException::Param("senderEmail", "Invalid sender e-mail address", $e->getCode());
        }

        // Timeout and TLS
        try {
            $timeOut = $this->input()->getInt("timeOut", true);
            if (!$timeOut) {
                throw new AdminAPIException('Timeout value is required');
            } elseif ($timeOut < 1 || $timeOut > 30) {
                throw new AdminAPIException('Timeout value is out of range (1-30 seconds)');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("timeOut");
            throw $e;
        }

        if ($this->mailConfig->setValue("timeOut", $timeOut)) {
            $changes++;
        }


        $tls = $this->input()->getUnsafe("tls");
        if (!$tls) {
            throw AdminAPIException::Param("tls", 'TLS encryption trigger is required');
        }

        if ($this->mailConfig->setValue("useTLS", Validator::getBool($tls))) {
            $changes++;
        }

        // Further setup as per mail service selected
        switch ($this->mailConfig->service) {
            case MailService::SMTP:
                $this->setupSMTP($changes);
                break;
            case MailService::MAILGUN:
                $this->setupMailGun($changes);
                break;
            default: // Do nothing further
                break;
        }

        // Changes?
        if (!$changes) {
            throw new AdminAPIException('There are no changes to be saved');
        }

        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $this->mailConfig->save();

            $this->adminLogEntry(
                sprintf('Mails configuration service "%s" updated', strtoupper($this->mailConfig->service->value)),
                flags: ["config", "mails-config"]
            );

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        // Clear Cached
        try {
            MailConfig::ClearCached();
        } catch (CacheException $e) {
            $this->aK->errors->trigger($e, E_USER_WARNING);
        }

        $this->status(true);
    }

    /**
     * @param int $changes
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     */
    private function setupSMTP(int &$changes): void
    {
        // Hostname
        try {
            $hostname = $this->input()->getASCII("hostname");
            if (!$hostname) {
                throw new AdminAPIException('SMTP hostname is required');
            } elseif (strlen($hostname) > 64) {
                throw new AdminAPIException('SMTP hostname cannot exceed 64 bytes');
            } elseif (!Validator::isValidHostname($hostname)) {
                throw new AdminAPIException('Invalid SMTP hostname');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("hostname");
            throw $e;
        }

        if ($this->mailConfig->setValue("hostname", $hostname)) {
            $changes++;
        }

        // Port
        try {
            $port = $this->input()->getInt("port", unSigned: true);
            if (!Validator::isValidPort($port, min: 25)) {
                throw new AdminAPIException('Invalid SMTP port');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("port");
            throw $e;
        }

        if ($this->mailConfig->setValue("port", $port)) {
            $changes++;
        }

        // Username
        try {
            $username = strval($this->input()->getUnsafe("username"));
            $usernameLen = strlen($username);
            if (!$username) {
                throw new AdminAPIException('SMTP username is required');
            } elseif ($usernameLen < 4) {
                throw new AdminAPIException('SMTP username must be 4 bytes long');
            } elseif ($usernameLen > 64) {
                throw new AdminAPIException('SMTP username must not exceed 64 bytes');
            } elseif (!Validator::isASCII($username, "-.=+:")) {
                throw new AdminAPIException('SMTP username contains an illegal character');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("username");
            throw $e;
        }

        if ($this->mailConfig->setValue("username", $username)) {
            $changes++;
        }

        // Password
        try {
            $password = $this->input()->getASCII("password");
            $passwordLen = strlen($password);
            if (!$password) {
                throw new AdminAPIException('SMTP password is required');
            } elseif ($passwordLen < 4) {
                throw new AdminAPIException('SMTP password must be 4 bytes long');
            } elseif ($passwordLen > 64) {
                throw new AdminAPIException('SMTP password must not exceed 64 bytes');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("password");
            throw $e;
        }

        if ($this->mailConfig->setValue("password", $password)) {
            $changes++;
        }

        // Server Name
        try {
            $serverName = $this->input()->getASCII("serverName");
            if (!$serverName) {
                throw new AdminAPIException('SMTP serverName is required');
            } elseif (strlen($serverName) > 40) {
                throw new AdminAPIException('SMTP serverName cannot exceed 40 bytes');
            } elseif (!Validator::isValidHostname($serverName)) {
                throw new AdminAPIException('Invalid SMTP serverName');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("serverName");
            throw $e;
        }

        if ($this->mailConfig->setValue("serverName", $serverName)) {
            $changes++;
        }
    }

    /**
     * @param int $changes
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     */
    private function setupMailGun(int &$changes): void
    {
        // API Key
        try {
            $apiKey = $this->input()->getASCII("mgApiKey");
            $apiKeyLen = strlen($apiKey);
            if (!$apiKey) {
                throw new AdminAPIException('API key is required');
            } elseif ($apiKeyLen < 8 || $apiKeyLen > 64) {
                throw new AdminAPIException('API key must be between 8 and 64 bytes long');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("mgApiKey");
            throw $e;
        }

        if ($this->mailConfig->setValue("mgApiKey", $apiKey)) {
            $changes++;
        }

        // Domain
        try {
            $apiDomain = strtolower($this->input()->getASCII("mgApiDomain"));
            if (!$apiDomain) {
                throw new AdminAPIException('MailGun user domain is required');
            } elseif (!Validator::isValidHostname($apiDomain)) {
                throw new AdminAPIException('Invalid MailGun user domain name');
            } elseif (str_starts_with($apiDomain, "www.")) {
                throw new AdminAPIException('MailGun user domain cannot begin with "www."');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("mgApiDomain");
            throw $e;
        }

        if ($this->mailConfig->setValue("mgApiDomain", $apiDomain)) {
            $changes++;
        }

        // API Region
        try {
            $apiRegion = strtolower($this->input()->getASCII("mgApiRegion"));
            if (!in_array($apiRegion, ["us", "eu"])) {
                throw new AdminAPIException('Invalid MailGun API server region');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("mgApiRegion");
            throw $e;
        }

        if ($this->mailConfig->setValue("mgEurope", $apiRegion === "eu")) {
            $changes++;
        }
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws AppException
     */
    public function get(): void
    {
        if (!$this->admin->privileges()->isRoot()) {
            if (!$this->admin->privileges()->viewConfig) {
                throw new AdminAPIException('You do not have privilege to view configuration');
            }
        }

        $this->status(true);
        $this->response->set("config", $this->mailConfig);
    }
}
