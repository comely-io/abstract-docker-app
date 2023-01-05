<?php
declare(strict_types=1);

namespace App\Services\Public\Controllers;

use App\Common\Database\PublicAPI\QueriesPayload;
use App\Common\DataStore\PublicAPIAccess;
use App\Common\Emails;
use App\Common\Exception\AppControllerException;
use App\Common\Kernel\ErrorHandler\Errors;
use App\Common\Kernel\Http\Controllers\AbstractAppController;
use App\Common\PublicAPI\Query;
use App\Common\PublicAPI\QueryPayload;
use App\Common\Validator;
use App\Services\Public\Exception\PublicAPIException;
use App\Services\Public\PublicAPIService;
use Comely\Database\Exception\DatabaseException;
use Comely\Database\Schema;
use Comely\Http\Common\HttpMethod;
use FurqanSiddiqui\SemaphoreEmulator\Exception\ConcurrentRequestBlocked;
use FurqanSiddiqui\SemaphoreEmulator\Exception\ConcurrentRequestTimeout;
use FurqanSiddiqui\SemaphoreEmulator\Exception\ResourceLockException;
use FurqanSiddiqui\SemaphoreEmulator\ResourceLock;

/**
 * Class AbstractPublicAPIController
 * @method get(): void
 * @method post(): void
 * @method put(): void
 * @method delete(): void
 * @package App\Services\Public
 */
abstract class AbstractPublicAPIController extends AbstractAppController
{
    /** @var bool Log query and payload data? */
    protected const QUERY_LOGGING = false;
    /** @var array Query logging: Ignore following params from request body */
    public const QL_IGNORE_REQ_PARAMS = [];
    /** @var bool Query logging: Save request params? */
    public const QL_SAVE_REQ_PARAMS = true;
    /** @var bool Query logging: Save response body? */
    public const QL_SAVE_RES_BODY = true;
    /** @var bool Semaphore locking by IP address */
    protected const SEMAPHORE_IP_LOCK = false;
    /** @var bool Allow con-current requests by HTTP method GET */
    protected const SEMAPHORE_ALLOW_CONCURRENT_GETS = false;

    /** @var PublicAPIService */
    protected readonly PublicAPIService $aK;
    /** @var PublicAPIAccess */
    protected readonly PublicAPIAccess $apiAccess;
    /** @var string */
    protected readonly string $ipAddress;
    /** @var array */
    protected readonly array $httpHeaderAuth;
    /** @var Query|null */
    public ?Query $queryLog = null;
    /** @var ResourceLock|null */
    public ?ResourceLock $semaphoreIPLock = null;
    /** @var \App\Common\Emails|null */
    protected ?Emails $emails = null;

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     */
    public function callback(): void
    {
        // AppKernel instance
        $this->aK = PublicAPIService::getInstance();

        // Load Public API Config
        $this->apiAccess = PublicAPIAccess::getInstance(true);

        // Default response type (despite any ACCEPT header)
        $this->response->header("content-type", "application/json");

        // Prepare response
        $this->response->set("status", false);

        // Controller method
        $httpRequestMethod = strtolower($this->request->method->toString());

        // Execute
        try {
            if (!method_exists($this, $httpRequestMethod)) {
                if ($httpRequestMethod === "options") {
                    $this->response->set("status", true);
                    $this->response->set("options", []);
                    return;
                } else {
                    throw new AppControllerException(
                        sprintf('Endpoint "%s" does not support "%s" method', static::class, strtoupper($httpRequestMethod))
                    );
                }
            }

            $this->onLoad(); // Event callback: onLoad
            call_user_func([$this, $httpRequestMethod]);
        } catch (\Exception $e) {
            $this->response->set("status", false);
            $this->response->set("error", $e->getMessage());

            if ($e instanceof PublicAPIException) {
                $param = $e->getParam();
                if ($param) {
                    $this->response->set("param", $param);
                }

                $data = $e->getData();
                $this->response->set("errorData", $data);
            }

            if ($this->aK->isDebug()) {
                $this->response->set("caught", get_class($e));
                $this->response->set("file", $e->getFile());
                $this->response->set("line", $e->getLine());
                $this->response->set("trace", $this->getExceptionTrace($e));
            }
        }

        $displayErrors = $this->aK->isDebug() ?
            $this->aK->errors->all() :
            $this->aK->errors->triggered()->array();

        if ($displayErrors) {
            $this->response->set("errors", $displayErrors); // Errors
        }

        $this->onFinish(); // Event callback: onFinish
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppDirException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DbConnectionException
     * @throws \Comely\Filesystem\Exception\PathException
     * @throws \Comely\Mailer\Exception\MailerException
     */
    protected function initEmailsComponent(): void
    {
        if ($this->emails) {
            return;
        }

        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\MailsQueue');

        $this->emails = new Emails($this->aK);
    }

    /**
     * @param bool $status
     * @return $this
     */
    protected function status(bool $status): static
    {
        $this->response->set("status", $status);
        return $this;
    }

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \Exception
     */
    private function enableQueryLogging(): void
    {
        $apiLogsDb = $this->aK->db->apiLogs();
        Schema::Bind($apiLogsDb, 'App\Common\Database\PublicAPI\Queries');
        Schema::Bind($apiLogsDb, 'App\Common\Database\PublicAPI\QueriesPayload');

        // Seed the Query Log
        try {
            $this->queryLog = new Query();
            $this->queryLog->id = 0;
            $this->queryLog->set("checksum", "tba");
            $this->queryLog->ipAddress = $this->ipAddress;
            $this->queryLog->method = $this->request->method->toString();
            $this->queryLog->endpoint = $this->request->url->complete;
            $this->queryLog->startOn = microtime(true);
            $this->queryLog->endOn = doubleval(0);
            $this->queryLog->query()->insert();
            $this->queryLog->id = $apiLogsDb->lastInsertId();
            $this->queryLog->set("checksum", $this->queryLog->checksum()->raw());
            $this->queryLog->query()->where("id", $this->queryLog->id)->update();
        } catch (DatabaseException $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new PublicAPIException('Failed to seed query log entry');
        }

        // Enable output buffer
        $publicAPIService = $this->aK;
        $controller = $this;
        if (!ob_start()) {
            throw new PublicAPIException('Failed to initialise output buffer');
        }

        register_shutdown_function(function () use ($controller, $publicAPIService) {
            $buffered = ob_get_contents();
            if (!$buffered) {
                $buffered = null;
            }

            ob_end_clean();

            try {
                $queryLog = $controller->queryLog();
                if ($queryLog) {
                    $queryLog->resCode = $controller->response->getHttpStatusCode();
                    $queryLog->endOn = microtime(true);
                    $queryPayload = new QueryPayload($queryLog, $controller, $buffered);
                    $encryptedPayload = $publicAPIService->ciphers->secondary()->encrypt($queryPayload);
                    $queryLog->resLen = $encryptedPayload->len();
                    $queryLog->set("checksum", $queryLog->checksum()->raw());
                    $controller->queryLog->query()->where("id", $controller->queryLog->id)->update();

                    $publicAPIService->db->apiLogs()->query()->table(QueriesPayload::TABLE)->insert([
                        "query" => $queryLog->id,
                        "encrypted" => $encryptedPayload->raw()
                    ]);
                }
            } catch (\Exception $e) {
                // Write the log
                if (isset($queryLog)) {
                    $data[] = Errors::Exception2String($e);
                    $data[] = $e->getTraceAsString();
                    $data[] = var_export($publicAPIService->errors->all(), true);
                    $data[] = "";

                    $publicAPIService->dirs->log()->dir("queries", true)->write(
                        sprintf('%s', dechex($queryLog->id)),
                        implode("\n\n", $data)
                    );
                }

                $publicAPIService->errors->triggerIfDebug($e, E_USER_WARNING);
            }

            print $buffered;
        });
    }

    /**
     * @return Query|null
     */
    final public function queryLog(): ?Query
    {
        return $this->queryLog;
    }

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     */
    private function enableSemaphoreIPLock(): void
    {
        if ($this->request->method === HttpMethod::GET) { // Request by HTTP method "GET" ?
            if (static::SEMAPHORE_ALLOW_CONCURRENT_GETS) { // Concurrent requests allowed?
                return;
            }
        }

        try {
            $resourceLock = $this->aK->semaphoreEmulator()
                ->obtainLock(sprintf("public_api_ip_%s", md5($this->ipAddress)));
            $this->semaphoreIPLock = $resourceLock;
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
     */
    final protected function onLoad(): void
    {
        // Validate IP Address
        if (!Validator::isValidIP($this->userClient->ipAddress)) {
            throw new PublicAPIException('INVALID_IP_ADDRESS');
        }

        // Determine which IP address should be used everywhere (ipAddress vs realIpAddress prop)
        $this->ipAddress = $this->userClient->ipAddress;

        // Global Status Check
        if (!$this->apiAccess->globalStatus) {
            throw new PublicAPIException('PUBLIC_API_DISABLED');
        }

        // Query Logging?
        if (static::QUERY_LOGGING) {
            $this->enableQueryLogging();
        }

        // Semaphore IP Locking?
        if (static::SEMAPHORE_IP_LOCK) {
            $this->enableSemaphoreIPLock();
        }

        // Http Authorization Headers
        $authHeaders = [];
        $authTokens = explode(",", strval($this->request->headers->get("authorization")));
        foreach ($authTokens as $authToken) {
            $authToken = explode(" ", trim($authToken));
            $authHeaders[strtolower($authToken[0])] = trim(strval($authToken[1] ?? null));
        }

        $this->httpHeaderAuth = $authHeaders;

        // Public API callback
        $this->publicAPICallback();
    }

    /**
     * @return void
     */
    abstract protected function publicAPICallback(): void;

    /**
     * @return void
     */
    protected function onFinish(): void
    {
    }

    /**
     * @return string
     */
    final protected function getAccessAppDeviceType(): string
    {
        return "web";
    }
}
