<?php
declare(strict_types=1);

namespace App\Services\Public\Controllers\Session;

use App\Common\DataStore\ProgramConfig;
use App\Common\DataStore\RecaptchaStatus;
use App\Common\PublicAPI\Session;
use App\Services\Public\Controllers\AbstractPublicAPIController;
use Comely\Database\Schema;

/**
 * Class AbstractSessionAPIController
 * @package App\Services\Public\Controllers\Session
 */
abstract class AbstractSessionAPIController extends AbstractPublicAPIController
{
    /** @var bool Queries logged enabled by default for all sub-controllers/endpoints */
    protected const QUERY_LOGGING = true;
    /** @var bool Semaphore locking by IP address enabled by default */
    protected const SEMAPHORE_IP_LOCK = true;
    /** @var bool Concurrent request to "GET" allowed by default */
    protected const SEMAPHORE_ALLOW_CONCURRENT_GETS = true;
    /** @var int Bypass dynamic ReCaptcha in-between timer */
    protected const RECAPTCHA_DYNAMIC_TIMESPAN = 1800;

    /** @var Session */
    protected readonly Session $session;

    /**
     * @return void
     */
    abstract protected function sessionAPICallback(): void;

    final protected function publicAPICallback(): void
    {
        // Scheme Bind
        $apiLogsDb = $this->aK->db->apiLogs();
        Schema::Bind($apiLogsDb, 'App\Common\Database\PublicAPI\Sessions');

        // Validate Session


        // Callback method for implementing endpoints
        $this->sessionAPICallback();
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
