<?php
declare(strict_types=1);

namespace App\Services\Admin\Controllers\Auth;

use App\Common\Database\DbBackup;
use App\Common\Database\Primary\DbBackups;
use App\Common\Engine\DbBackupQuery;
use App\Services\Admin\Exception\AdminAPIException;
use Comely\Cache\Exception\CacheException;
use Comely\Database\Exception\ORM_ModelNotFoundException;
use Comely\Database\Schema;
use Comely\Database\Server\DbCredentials;

/**
 * Class Dbs
 * @package App\Services\Admin\Controllers\Auth
 */
class Dbs extends AuthAdminAPIController
{
    /**
     * @return void
     * @throws \Comely\Database\Exception\DbConnectionException
     */
    protected function authCallback(): void
    {
        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\DbBackups');
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function queueDbBackup(): void
    {
        if ($this->hasPendingBackupJob()) {
            throw new AdminAPIException('App daemon queue is currently busy');
        }

        // Database
        try {
            $dbName = $this->input()->getASCII("database");
            if (!$dbName) {
                throw new AdminAPIException('Database is required');
            }

            $dbCred = $this->aK->config->db->get($dbName);
            if (!$dbCred) {
                throw new AdminAPIException('No such database is configured');
            }

            if ($dbCred->driver !== "mysql") {
                throw new AdminAPIException(sprintf('Database "%s" is not a MySQL database', $dbCred->dbname));
            }
        } catch (AdminAPIException $e) {
            $e->setParam("database");
            throw $e;
        }

        // Verify Totp
        $this->totpVerify($this->input()->getASCII("totp"));

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $this->aK->cache->set(
                "app.engine.daemonQuery",
                (new DbBackupQuery($dbCred->dbname))
            );

            $this->adminLogEntry(sprintf('Database "%s" backup job queued to app daemon', $dbCred->dbname), flags: ["db-backup"]);

            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->status(true);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws ORM_ModelNotFoundException
     * @throws \App\Common\Exception\AppDirException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Filesystem\Exception\FilesystemException
     */
    private function deleteDbBackup(): void
    {
        $backup = $this->fetchDbBackup();

        // Verify Totp
        $this->totpVerify($this->input()->getASCII("totp"));

        // Read backup file
        $backupsDir = $this->aK->dirs->backups();
        $backupFile = $backupsDir->file($backup->filename . ".zip", createIfNotExists: false);

        if (!$backupFile->permissions()->readable()) {
            throw new AdminAPIException('Backup file is not readable; Permission error');
        }

        $db = $this->aK->db->primary();
        $db->beginTransaction();

        try {
            $backupFile->delete();
            $backup->query()->delete();
            $this->adminLogEntry(sprintf('Database "%s" backup [#%d] deleted', $backup->db, $backup->id), flags: ["db-backup"]);
            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }

        $this->status(true);
    }

    /**
     * @return bool
     */
    private function hasPendingBackupJob(): bool
    {
        try {
            $daemonQuery = $this->aK->cache->get("app.engine.daemonQuery");
            if (isset($daemonQuery)) {
                return true;
            }
        } catch (CacheException) {
        }

        return false;
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws ORM_ModelNotFoundException
     * @throws \App\Common\Exception\AppDirException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Filesystem\Exception\FilesystemException
     */
    public function post(): void
    {
        switch (strtolower($this->input()->getASCII("action"))) {
            case "queue":
                $this->queueDbBackup();
                return;
            case "delete":
                $this->deleteDbBackup();
                return;
            default:
                throw AdminAPIException::Param("action", "Invalid action called");
        }
    }

    /**
     * @return void
     */
    private function getDbsConfig(): void
    {
        $dbConfigs = $this->aK->config->db->getAll();
        $result = [];

        /** @var DbCredentials $dbConfig */
        foreach ($dbConfigs as $label => $dbConfig) {
            $result[$label] = [
                "driver" => $dbConfig->driver,
                "host" => $dbConfig->host,
                "port" => $dbConfig->port,
                "name" => $dbConfig->dbname,
            ];
        }


        $this->status(true);
        $this->response->set("config", $result);
        $this->response->set("backupQueueBusy", $this->hasPendingBackupJob());
    }

    /**
     * @return DbBackup
     * @throws AdminAPIException
     * @throws ORM_ModelNotFoundException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\ORM_Exception
     * @throws \Comely\Database\Exception\SchemaTableException
     */
    private function fetchDbBackup(): DbBackup
    {
        if (!$this->admin->privileges()->isRoot()) {
            if (!$this->admin->privileges()->downloadDbBackups) {
                throw new AdminAPIException('You do not have privilege to access DB backups');
            }
        }

        try {
            $backupId = $this->input()->getInt("id");
            if (!($backupId > 0)) {
                throw new AdminAPIException('Invalid backup ID');
            }

            /** @var DbBackup $backup */
            $backup = DbBackups::Find()->query('WHERE `id`=?', [$backupId])->first();
        } catch (AdminAPIException $e) {
            $e->setParam("id");
            throw $e;
        }

        return $backup;
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws ORM_ModelNotFoundException
     * @throws \App\Common\Exception\AppDirException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Filesystem\Exception\FilesystemException
     */
    private function downloadBackup(): void
    {
        $backup = $this->fetchDbBackup();

        // Read backup file
        $backupsDir = $this->aK->dirs->backups();
        $backupFile = $backupsDir->file($backup->filename . ".zip", createIfNotExists: false);

        if (!$backupFile->permissions()->readable()) {
            throw new AdminAPIException('Backup file is not readable; Permission error');
        }

        set_time_limit(0);
        header("Content-type: application/octet-stream;");
        header("Content-Disposition: attachment; filename=" . $backup->db . "_" . date("d-m-Y_H:i", $backup->epoch) . ".zip");
        header("Pragma: no-cache");
        header("Expires: 0");

        // Todo: Work in Progress

//        $fp = fopen($backupFile->path(), "rb");
//        $bytes = fread($fp, $backupFile->size() + 1);
//        fclose($fp);
//        print $bytes;

        readfile($backupFile->path());
        exit;
    }

    /**
     * @return void
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function getBackups(): void
    {
        try {
            $backups = DbBackups::Find()->query('WHERE 1 ORDER BY `epoch` DESC')->limit(100)->all();
        } catch (ORM_ModelNotFoundException) {
            $backups = [];
        }

        $this->status(true);
        $this->response->set("backups", $backups);
    }

    /**
     * @return void
     * @throws AdminAPIException
     * @throws ORM_ModelNotFoundException
     * @throws \App\Common\Exception\AppDirException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Filesystem\Exception\FilesystemException
     */
    public function get(): void
    {
        switch (strtolower($this->input()->getASCII("action"))) {
            case "config":
                $this->getDbsConfig();
                return;
            case "backups":
                $this->getBackups();
                return;
            case "download":
                $this->downloadBackup();
                return;
            default:
                throw AdminAPIException::Param("action", "Invalid action called");
        }
    }
}
