<?php
declare(strict_types=1);

namespace App\Services\Public\Controllers;

use App\Common\AppConstants;
use App\Common\Database\PublicAPI\Sessions;
use App\Services\Public\Exception\PublicAPIException;
use Comely\Database\Schema;
use Comely\Security\PRNG;

/**
 * Class Session
 * @package App\Services\Public\Controllers
 */
class Session extends AbstractPublicAPIController
{
    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function publicAPICallback(): void
    {
        $apiDb = $this->aK->db->apiLogs();
        Schema::Bind($apiDb, 'App\Common\Database\PublicAPI\Sessions');
    }

    /**
     * @return void
     * @throws PublicAPIException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Security\Exception\PRNG_Exception
     */
    public function post(): void
    {
        $sessionToken = $this->httpHeaderAuth[strtolower(AppConstants::PUBLIC_API_HEADER_SESS_TOKEN)] ?? null;
        if ($sessionToken) {
            throw new PublicAPIException("SESSION_TOKEN_EXISTS");
        }

        $timeStamp = time();
        $apiDb = $this->aK->db->apiLogs();
        $recentIssued2IPTokens = $apiDb->query()->table(Sessions::TABLE)
            ->where('`ip_address`=? AND `issued_on`>=?', [$this->ipAddress, $timeStamp - 60])
            ->fetch();

        if ($recentIssued2IPTokens->count()) {
            throw new PublicAPIException("SESSION_CREATE_TIMEOUT");
        }

        $secureEntropy = PRNG::randomBytes(32);
        $session = new \App\Common\PublicAPI\Session();
        $session->id = 0;
        $session->set("checksum", "tba");
        $session->type = $this->getAccessAppDeviceType();
        $session->archived = 0;
        $session->set("token", $secureEntropy);
        $session->ipAddress = $this->ipAddress;
        $session->issuedOn = $timeStamp;
        $session->lastUsedOn = $timeStamp;
        $session->query()->insert();
        $session->id = $apiDb->lastInsertId();
        $session->set("checksum", $session->checksum()->raw());
        $session->query()->where("id", $session->id)->update();

        $this->status(true);
        $this->response->set("session", [
            "token" => bin2hex($secureEntropy),
            "validFor" => $this->ipAddress,
            "deviceType" => $session->type
        ]);
    }
}
