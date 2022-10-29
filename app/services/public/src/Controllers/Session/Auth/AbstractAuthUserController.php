<?php
declare(strict_types=1);

namespace App\Services\Public\Controllers\Session\Auth;

use App\Common\AppConstants;
use App\Common\Database\Primary\Users;
use App\Common\Users\User;
use App\Services\Public\Controllers\Session\AbstractSessionAPIController;
use App\Services\Public\Exception\PublicAPIException;

/**
 * Class AbstractAuthUserController
 * @package App\Services\Public\Controllers\Session\Auth
 */
abstract class AbstractAuthUserController extends AbstractSessionAPIController
{
    /** @var bool Validate request payload HMAC signature */
    protected const HMAC_REQUEST_VALIDATION = true;
    /** @var array Ignore following request params in HMAC compute */
    protected const HMAC_IGNORE_PARAMS = [];

    /** @var User */
    protected readonly User $user;

    /**
     * @return void
     */
    abstract protected function authCallback(): void;

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     * @throws \App\Common\Exception\AppModelNotFoundException
     */
    final protected function sessionAPICallback(): void
    {
        // Authenticate User
        $this->authenticate();

        // Callback method for implementing endpoints
        $this->authCallback();
    }

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     * @throws \App\Common\Exception\AppModelNotFoundException
     */
    private function authenticate(): void
    {
        if (!$this->session->authUserId) {
            throw new PublicAPIException('SESSION_AUTH_NA');
        }

        $this->user = Users::Get(id: $this->session->authUserId, useCache: true);
        $this->user->validateChecksum();

        // User status check
        if ($this->user->status !== "active") {
            throw new PublicAPIException('SESSION_AUTH_USER_DISABLED');
        }

        // Cross-check session IDs; (User may have logged in from elsewhere)
        $userAuthToken = $this->user->private($this->session->type . "AuthToken");
        if (!is_string($userAuthToken) || strlen($userAuthToken) !== 48) {
            throw new PublicAPIException('Invalid user device token');
        }

        if (substr($userAuthToken, 0, 32) !== $this->session->private("token")) {
            throw new PublicAPIException('SESSION_REDUNDANT');
        }

        // Validate HMAC
        if (static::HMAC_REQUEST_VALIDATION) {
            $userHMACSecret = substr($userAuthToken, 32);
            $excludeBodyParams = array_map("strtolower", static::HMAC_IGNORE_PARAMS);

            // Request params
            $payload = [];
            foreach ($this->input()->array() as $key => $value) {
                if (in_array(strtolower($key), $excludeBodyParams)) {
                    $value = "";
                }

                $payload[$key] = $value;
            }

            $queryString = http_build_query($payload, "", "&", PHP_QUERY_RFC3986);

            // Calculate HMAC
            $hmac = hash_hmac("sha512", $queryString, $userHMACSecret, false);
            if (!$hmac) {
                throw new PublicAPIException('Failed to generate cross-check HMAC signature');
            }

            if ($this->httpHeaderAuth[AppConstants::PUBLIC_API_HEADER_CLIENT_SIGN] !== $hmac) {
                throw new PublicAPIException('REQUEST_HMAC_FAIL');
            }

            // Timestamp
            $requestTsAge = time() - $this->input()->getInt("timeStamp");
            if ($requestTsAge >= 6) {
                $this->aK->errors->triggerIfDebug(
                    sprintf('The request query has expired, -%d seconds', $requestTsAge),
                    E_USER_WARNING
                );

                throw new PublicAPIException('REQUEST_EXPIRED');
            }
        }
    }

    /**
     * @param mixed $code
     * @param string|null $param
     * @param bool $allowReuse
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     */
    protected function totpVerify(mixed $code, ?string $param = "totp", bool $allowReuse = false): void
    {
        if (is_int($code)) {
            $code = strval($code);
        }

        try {
            if (!is_string($code) || !preg_match('/^\d{6}$/', $code)) {
                throw new PublicAPIException('TOTP_INVALID');
            }

            if (!$allowReuse) {
                if ($code === $this->session->last2faCode) {
                    throw new PublicAPIException('TOTP_CONSUMED');
                }
            }

            if (!$this->user->credentials()->verifyTotp($code)) {
                throw new PublicAPIException('TOTP_INCORRECT');
            }
        } catch (PublicAPIException $e) {
            if ($param) {
                $e->setParam($param);
            }

            throw $e;
        }

        $this->session->last2faOn = time();
        $this->session->last2faCode = $code;
    }
}
