<?php
declare(strict_types=1);

namespace App\Services\Public\Controllers\Session;

use App\Common\Database\Primary\Users;
use App\Services\Public\Exception\PublicAPIException;
use App\Services\Public\PublicUserAccount;
use Comely\Database\Schema;

/**
 * Class Meta
 * @package App\Services\Public\Controllers\Session
 */
class Meta extends AbstractSessionAPIController
{
    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function sessionAPICallback(): void
    {
        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Users');
    }

    /**
     * @return void
     * @throws \Comely\Database\Exception\ORM_ModelQueryException
     */
    public function delete(): void
    {
        $this->session->archived = 1;
        $this->session->query()->update();
        $this->status(true);
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \App\Common\Exception\AppModelNotFoundException
     */
    public function get(): void
    {
        $authUserData = null;
        if ($this->session->authUserId) {
            $authUser = Users::Get(id: $this->session->authUserId, useCache: true);
            $authUser->validateChecksum();

            if (substr(strval($authUser->private($this->session->type . "AuthToken")), 0, 32) === $this->session->private("token")) {
                $authUserData = new PublicUserAccount($authUser);
            } else {
                // User has possibly logged in elsewhere
                throw new PublicAPIException('SESSION_REDUNDANT');
            }
        }

        $this->status(true);
        $this->response->set("session", [
            "deviceType" => $this->session->type,
            "authUser" => $authUserData,
            "auth2fa" => $this->session->authSessionOtp === 1,
            "issuedOn" => $this->session->issuedOn,
            "lastUsedOn" => $this->session->lastUsedOn
        ]);
    }
}
