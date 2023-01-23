<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth\PublicApi;

use App\Common\Database\Primary\Users;
use App\Common\PublicAPI\Session;
use App\Common\Validator;
use App\Services\Admin\Controllers\Auth\AuthAdminAPIController;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Database\Exception\ORM_ModelNotFoundException;
use Comely\Database\Schema;

/**
 * Class Sessions
 * @package App\Services\Admin\Controllers\Auth\PublicApi
 */
class Sessions extends AuthAdminAPIController
{
    /** @var int[] */
    private const PER_PAGE_OPTS = [50, 100, 250];

    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function authCallback(): void
    {
        $apiLogsDb = $this->aK->db->apiLogs();
        Schema::Bind($apiLogsDb, 'App\Common\Database\PublicAPI\Sessions');

        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Users');
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \App\Services\Admin\Exception\AdminAPIException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    public function delete(): void
    {
        try {
            $sessionId = $this->input()->getInt("sessionId");
            if ($sessionId <= 0) {
                throw new AdminAPIException('Invalid session ID');
            }

            try {
                /** @var \App\Common\PublicAPI\Session $session */
                $session = \App\Common\Database\PublicAPI\Sessions::Find(["id" => $sessionId])->first();
            } catch (ORM_ModelNotFoundException) {
                throw new AdminAPIException('No such public API session exists');
            }

            if ($session->archived === 1) {
                throw new AdminAPIException('This session is already archived');
            }
        } catch (AdminAPIException $e) {
            $e->setParam("sessionId");
            throw $e;
        }

        $needOtp = !($this->session->last2faOn && (time() - $this->session->last2faOn) <= 120);
        if ($needOtp) {
            $this->totpVerify($this->input()->getASCII("totp"), allowReuse: true);
        }

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $session->archived = 1;
            $session->query()->update();
            $this->adminLogEntry(sprintf('Public API session %d archived', $session->id), flags: ["pub-sess:" . $session->id]);
            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->status(true);
    }

    /**
     * @param \App\Common\PublicAPI\Session $session
     * @return array
     * @throws \App\Common\Exception\AppException
     */
    private function getSessionPublicArray(Session $session): array
    {
        $token = $session->private("token");

        return [
            "id" => $session->id,
            "type" => $session->type,
            "archived" => $session->archived === 1,
            "checksumVerified" => $session->checksum()->raw() === $session->private("checksum"),
            "token" => [bin2hex(substr($token, 0, 3)), bin2hex(substr($token, -3))],
            "ipAddress" => $session->ipAddress,
            "userAgent" => $session->userAgent,
            "fingerprint" => bin2hex($session->fingerprint),
            "authUserId" => $session->authUserId,
            "authSessionOtp" => $session->authSessionOtp === 1,
            "last2faOn" => $session->last2faOn,
            "lastRecaptchaOn" => $session->lastRecaptchaOn,
            "issuedOn" => $session->issuedOn,
            "lastUsedOn" => $session->lastUsedOn,
        ];
    }

    /**
     * @param int $sessionId
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function getInputSession(int $sessionId): void
    {
        /** @var \App\Common\PublicAPI\Session $session */
        $session = \App\Common\Database\PublicAPI\Sessions::Find()->query('WHERE `id`=?', [$sessionId])->first();

        $this->status(true);
        $this->response->set("session", $this->getSessionPublicArray($session));
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppException
     * @throws \App\Services\Admin\Exception\AdminAPIException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    public function get(): void
    {
        $specificId = $this->input()->getInt("sessionId");
        if ($specificId > 0) {
            $this->getInputSession($specificId);
            return;
        }

        // Where Query
        $whereQuery = [];
        $whereData = [];

        // Match token
        $matchToken = strtolower($this->input()->getASCII("token"));
        if ($matchToken) {
            try {
                $isInt = preg_match('/^[0-9]+$/', $matchToken);
                if (!$isInt) {
                    if (!preg_match('/^[a-f0-9]{2,64}$/i', $matchToken)) {
                        throw new AdminAPIException('Invalid session token to match');
                    } elseif (strlen($matchToken) % 2 !== 0) {
                        throw new AdminAPIException('Session token must be of even length');
                    }

                    $whereQuery[] = '`token` LIKE ?';
                    $whereData[] = sprintf('%%%s%%', hex2bin($matchToken));
                } else {
                    $whereQuery[] = '`id`=?';
                    $whereData[] = intval($matchToken);
                }

            } catch (AdminAPIException $e) {
                $e->setParam("token");
                throw $e;
            }
        }

        // Archived
        $archived = strtolower($this->input()->getASCII("archived"));
        if (!$archived) {
            $archived = "exclude";
        }

        if (!in_array($archived, ["exclude", "include", "just"])) {
            throw AdminAPIException::Param("archived", "Invalid value for archived");
        }

        switch ($archived) {
            case "exclude":
                $whereQuery[] = "`archived`=0";
                break;
            case "just":
                $whereQuery[] = "`archived`=1";
                break;
        }

        // Authenticated User
        $user = strtolower($this->input()->getASCII("user"));
        if ($user) {
            try {
                try {
                    /** @var \App\Common\Users\User $user */
                    $user = Users::Find()->query('WHERE (`username`=:user OR `email`=:user OR `phone`=:user)', ["user" => $user])->first();
                } catch (ORM_ModelNotFoundException) {
                    throw new AdminAPIException('No such user account exists');
                }

                $whereQuery[] = "`auth_user_id`=?";
                $whereData[] = $user->id;
            } catch (AdminAPIException $e) {
                $e->setParam("user");
                throw $e;
            }
        }

        // IP Address
        $ipAddress = $this->input()->getASCII("ipAddress");
        if ($ipAddress) {
            try {
                if (preg_match('/[^a-f0-9.:]+/', $ipAddress)) {
                    throw new AdminAPIException('IP address contains invalid character');
                }

                if (Validator::isValidIP($ipAddress, true)) { // Complete IP address
                    $whereQuery = '`ip_address`=?';
                    $whereData[] = $ipAddress;
                } else { // Incomplete IP address
                    $whereQuery[] = '`ip_address` LIKE ?';
                    $whereData[] = sprintf('%%%s%%', $ipAddress);
                }
            } catch (AdminAPIException $e) {
                $e->setParam("ipAddress");
                throw $e;
            }
        }

        // Fingerprint
        $fingerprint = strtolower($this->input()->getASCII("fingerprint"));
        if ($fingerprint) {
            try {
                if (!preg_match('/^[a-f0-9]{2,64}$/i', $fingerprint)) {
                    throw new AdminAPIException('Invalid fingerprint to match');
                } elseif (strlen($matchToken) % 2 !== 0) {
                    throw new AdminAPIException('Fingerprint must be of even length');
                }

                $whereQuery[] = '`fingerprint` LIKE ?';
                $whereData[] = sprintf('%%%s%%', hex2bin($fingerprint));
            } catch (AdminAPIException $e) {
                $e->setParam("fingerprint");
                throw $e;
            }
        }

        // Sort By
        $sortBy = strtolower($this->input()->getASCII("sort"));
        if (!$sortBy) {
            $sortBy = "desc";
        }

        if (!in_array($sortBy, ["desc", "asc"])) {
            throw AdminAPIException::Param("sort", "Invalid sort value");
        }

        // Page Sorting
        $pageNum = $this->input()->getInt("page", true) ?? 1;
        $perPage = $this->input()->getInt("perPage", true) ?? self::PER_PAGE_OPTS[0];
        if (!in_array($perPage, self::PER_PAGE_OPTS)) {
            throw new AdminAPIException('Invalid value for "perPage" param');
        }

        if (!$whereQuery) {
            $whereQuery[] = 1;
        }

        // Result Prep
        $result = [
            "totalRows" => 0,
            "page" => null,
            "rows" => null
        ];

        try {
            $sessionsQuery = $this->aK->db->apiLogs()->query()
                ->table(\App\Common\Database\PublicAPI\Sessions::TABLE)
                ->where(implode(" AND ", $whereQuery), $whereData)
                ->start(($pageNum * $perPage) - $perPage)
                ->limit($perPage);

            if ($sortBy === "asc") {
                $sessionsQuery->asc("id");
            } else {
                $sessionsQuery->desc("id");
            }

            $sessionsQuery = $sessionsQuery->paginate();
            $result["totalRows"] = $sessionsQuery->totalRows();
            $result["page"] = $pageNum;
            $result["perPage"] = $perPage;
        } catch (\Exception $e) {
            $this->aK->errors->triggerIfDebug($e, E_USER_WARNING);
            throw new AdminAPIException('Failed to execute sessions fetch query');
        }

        $sessions = [];
        foreach ($sessionsQuery->rows() as $row) {
            unset($session);

            try {
                $session = new Session($row);
                $sessions[] = $session;
            } catch (\Exception $e) {
                $this->aK->errors->trigger($e, E_USER_WARNING);
                continue;
            }
        }

        $result["rows"] = $sessions;

        $this->status(true);
        $this->response->set("sessions", $result);
    }
}
