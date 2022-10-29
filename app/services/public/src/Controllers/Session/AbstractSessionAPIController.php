<?php
declare(strict_types=1);

namespace App\Services\Public\Controllers\Session;

use App\Common\AppConstants;
use App\Common\Database\PublicAPI\Sessions;
use App\Common\DataStore\ProgramConfig;
use App\Common\DataStore\RecaptchaStatus;
use App\Common\PublicAPI\Session;
use App\Services\Public\Controllers\AbstractPublicAPIController;
use App\Services\Public\Exception\PublicAPIException;
use Comely\Database\Exception\ORM_ModelNotFoundException;
use Comely\Database\Schema;
use Comely\Http\Common\HttpMethod;
use FurqanSiddiqui\SemaphoreEmulator\Exception\ConcurrentRequestBlocked;
use FurqanSiddiqui\SemaphoreEmulator\Exception\ConcurrentRequestTimeout;
use FurqanSiddiqui\SemaphoreEmulator\Exception\ResourceLockException;
use FurqanSiddiqui\SemaphoreEmulator\ResourceLock;

/**
 * Class AbstractSessionAPIController
 * @package App\Services\Public\Controllers\Session
 */
abstract class AbstractSessionAPIController extends AbstractPublicAPIController
{
    /** @var bool Queries logged enabled by default for all sub-controllers/endpoints */
    protected const QUERY_LOGGING = true;
    /** @var bool Semaphore locking by SESSION Token */
    protected const SEMAPHORE_SESSION_LOCK = true;
    /** @var bool Semaphore locking by IP address enabled by default */
    protected const SEMAPHORE_IP_LOCK = false;
    /** @var bool Concurrent request to "GET" allowed by default */
    protected const SEMAPHORE_ALLOW_CONCURRENT_GETS = true;
    /** @var int Bypass dynamic ReCaptcha in-between timer */
    protected const RECAPTCHA_DYNAMIC_TIMESPAN = 1800;

    /** @var Session */
    protected readonly Session $session;
    /** @var ResourceLock|null */
    protected ?ResourceLock $semaphoreSessLock = null;

    /**
     * @return void
     */
    abstract protected function sessionAPICallback(): void;

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    final protected function publicAPICallback(): void
    {
        // Initiate Session
        $this->initSession();

        // Semaphore Session Locking
        if (static::SEMAPHORE_SESSION_LOCK) {
            $this->enableSemaphoreSessionLock();
        }

        // Callback method for implementing endpoints
        $this->sessionAPICallback();
    }

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     */
    private function enableSemaphoreSessionLock(): void
    {
        if ($this->request->method === HttpMethod::GET) { // Request by HTTP method "GET" ?
            if (static::SEMAPHORE_ALLOW_CONCURRENT_GETS) { // Concurrent requests allowed?
                return;
            }
        }

        try {
            $resourceLock = $this->aK->semaphoreEmulator()
                ->obtainLock(sprintf("public_api_sess_%d", $this->session->id));
            $this->semaphoreSessLock = $resourceLock;
            register_shutdown_function(function () use ($resourceLock) {
                $resourceLock->release();
            });
        } catch (ResourceLockException $e) {
            if ($e instanceof ConcurrentRequestBlocked) {
                throw new PublicAPIException('CONCURRENT_REQUEST_BLOCKED');
            } elseif ($e instanceof ConcurrentRequestTimeout) {
                throw new PublicAPIException('CONCURRENT_REQUEST_TIMEOUT');
            }

            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new PublicAPIException('Concurrent requests validation fail');
        }
    }

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function initSession(): void
    {
        // Scheme Bind
        $apiLogsDb = $this->aK->db->apiLogs();
        Schema::Bind($apiLogsDb, 'App\Common\Database\PublicAPI\Sessions');

        // Validate Session
        $sessionToken = $this->httpHeaderAuth[strtolower(AppConstants::PUBLIC_API_HEADER_SESS_TOKEN)] ?? null;
        if (!$sessionToken) {
            throw new PublicAPIException('SESSION_TOKEN_REQUIRED');
        }

        if (!is_string($sessionToken) || !preg_match('/^[a-f0-9]{64}$/i', $sessionToken)) {
            throw new PublicAPIException('SESSION_TOKEN_INVALID');
        }

        try {
            /** @var Session $session */
            $session = Sessions::Find()->query('WHERE `token`=?', [hex2bin($sessionToken)])->first();
        } catch (ORM_ModelNotFoundException) {
            throw new PublicAPIException('SESSION_NOT_FOUND');
        } catch (\Exception $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new PublicAPIException('SESSION_RETRIEVE_ERROR');
        }

        // Validate Checksum
        if ($session->checksum()->raw() !== $session->private("checksum")) {
            throw new PublicAPIException('SESSION_CHECKSUM_FAIL');
        }

        // Device Type
        if ($session->type !== $this->getAccessAppDeviceType()) {
            throw new PublicAPIException('SESSION_APP_TYPE_ERROR');
        }

        // Is Archived?
        if ($session->archived !== 0) {
            throw new PublicAPIException('SESSION_ARCHIVED');
        }

        // IP Address Crosscheck
        if ($session->ipAddress !== $this->ipAddress) {
            throw new PublicAPIException('SESSION_IP_ERROR');
        }

        if ($session->type !== "app" && (time() - $session->lastUsedOn) >= 3600) {
            throw new PublicAPIException('SESSION_TIMED_OUT');
        }

        // Update the session lastUsedOn & checksum
        if (static::class !== 'App\Services\Public\Controllers\Session') {
            $session->lastUsedOn = time();
            $session->set("checksum", $session->checksum()->raw());
        }

        // Update session on query end
        register_shutdown_function([$this, "updateSession"]);

        // Set the instance
        $this->session = $session;
    }

    /**
     * @return void
     * @throws \Comely\Database\Exception\DatabaseException
     */
    public function updateSession(): void
    {
        if ($this->session->changes()) {
            $this->session->query()->update(expectPositiveRowCount: false);
        }
    }

    /**
     * @return string
     */
    final protected function getAccessAppDeviceType(): string
    {
        return "web";
    }

    /**
     * @return bool
     * @throws \App\Common\Exception\AppException
     */
    final public function isReCaptchaRequired(): bool
    {
        if ($this->session->type !== "web") {
            return false;
        }

        $reCaptchaConfig = ProgramConfig::getInstance(useCache: true)->reCaptcha;
        if (!$reCaptchaConfig && $reCaptchaConfig->status === RecaptchaStatus::DISABLED) {
            return false;
        }

        if (!$reCaptchaConfig->publicKey || !$reCaptchaConfig->privateKey) {
            return false;
        }

        switch ($reCaptchaConfig->status) {
            case RecaptchaStatus::ENABLED:
                return true;
            case RecaptchaStatus::DYNAMIC:
                if ($this->session->lastRecaptchaOn) {
                    if ((time() - $this->session->lastRecaptchaOn) < static::RECAPTCHA_DYNAMIC_TIMESPAN) {
                        return false;
                    }
                }

                return true;
            default:
                return false;
        }
    }
}
