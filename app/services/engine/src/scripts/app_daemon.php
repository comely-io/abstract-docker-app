<?php
declare(strict_types=1);

namespace bin;

use App\Common\Database\DbBackup;
use App\Common\Database\Primary\Admin\Logs;
use App\Common\Database\Primary\Admin\Sessions;
use App\Common\Database\Primary\DbBackups;
use App\Common\Database\PublicAPI\Queries;
use App\Common\Database\PublicAPI\QueriesPayload;
use App\Common\DataStore\SystemConfig;
use App\Common\Engine\DbBackupQuery;
use App\Common\Exception\AppException;
use App\Common\Kernel\CLI\AbstractCLIScript;
use App\Common\Kernel\Databases;
use Comely\Database\Exception\ORM_ModelNotFoundException;
use Comely\Database\Schema;
use Comely\Database\Server\DbCredentials;
use Comely\Filesystem\Exception\PathException;
use Comely\Utils\Time\TimeUnits;

/**
 * Class app_daemon
 * @package bin
 */
class app_daemon extends AbstractCLIScript
{
    /** @var SystemConfig */
    private SystemConfig $systemConfig;

    /**
     * @return void
     */
    public function exec(): void
    {
        parent::exec(); // inheritance call for Semaphore process locking

        $db = $this->aK->db->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\DbBackups');

        // Sleep for 120 seconds
        $this->print("{cyan}Starting in 60 seconds...{/}");
        sleep(60);
        $this->print("");

        // Bootstrap next cron exec
        $nextCronExec = time() - 1;

        while (true) {
            $this->print("{grey}[" . date("d M Y H:i:s") . "]{/}");

            $timeStamp = time();
            if ($timeStamp >= $nextCronExec) {
                $this->runSystemCron();

                // Set cron to run next hour at the top
                $nextCronExec = $timeStamp + (3600 - ($timeStamp % 3600));
            } else {
                $dQ = $this->aK->cache->get("app.engine.daemonQuery");
                if ($dQ) {
                    try {
                        if ($dQ instanceof DbBackupQuery && $dQ->dbName) {
                            $this->createDbBackup(false, $dQ->dbName);
                        }
                    } finally {
                        $this->aK->cache->delete("app.engine.daemonQuery");
                    }
                }
            }

            $this->updateExecTracker();
            sleep(20);
        }
    }

    /**
     * @param bool $isAuto
     * @param string $dbId
     * @return void
     * @throws AppException
     * @throws \App\Common\Exception\AppDirException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function createDbBackup(bool $isAuto, string $dbId): void
    {
        $tabs = str_repeat("\t", 1);
        $this->print("");
        $this->inline($tabs . "{cyan}Creating DB backup ");

        $dbId = strtolower($dbId);
        $dbCred = null;
        $dbConfigs = $this->aK->config->db->getAll();
        /**
         * @var string $label
         * @var DbCredentials $cred
         */
        foreach ($dbConfigs as $label => $cred) {
            if (strtolower($label) === $dbId) {
                $dbCred = $cred;
                break;
            }

            if (strtolower($cred->dbname) === $dbId) {
                $dbCred = $cred;
                break;
            }
        }

        if (!isset($dbCred)) {
            throw new AppException(sprintf('Could not retrieve configuration for DB "%s"', $dbId));
        }

        $this->inline("{green}{invert} " . $dbCred->dbname . " {/} ... ");

        if ($dbCred->driver !== "mysql") {
            throw new AppException('Database driver is not MySQL');
        }

        $dbPassword = $dbCred->password() ?? $this->aK->config->env->mysqlRootPassword ?? null;
        if (!$dbPassword) {
            throw new AppException(sprintf('No password defined for MySQL user "%s"', $dbCred->username()));
        }

        $backupsDir = $this->aK->dirs->backups();
        if (!chdir($backupsDir->path())) {
            throw new AppException('Cannot change to backups working directory');
        }

        try {
            $epoch = time();
            $filename = hash("sha1", sprintf("%s_%d", $dbCred->dbname, $epoch));
            $backupCmd = "/usr/bin/mysqldump -h " . $dbCred->host .
                " -u " . $dbCred->username() . " --password=" . $dbPassword . " " .
                $dbCred->dbname . " > " . $filename . ".sql";

            exec($backupCmd, result_code: $dumpResultCode);
            if ($dumpResultCode != 0) {
                throw new \RuntimeException('Failed to generate MySQL dump');
            }

            $archiveCmd = "zip ";
            if ($this->systemConfig->dbBackupPassword) {
                $archiveCmd .= "-P " . $this->systemConfig->dbBackupPassword . " ";
            }

            $archiveCmd .= $filename . ".zip " . $filename . ".sql";
            exec($archiveCmd, result_code: $zipCode);
            if ($zipCode != 0) {
                throw new \RuntimeException('Failed to create compressed archive of MySQL dump');
            }

            unlink($filename . ".sql");
            $filesize = @filesize($backupsDir->suffix($filename . ".zip"));
            if (!$filesize) {
                throw new \RuntimeException('Could not retrieve final filesize in bytes');
            }

            $backupEntry = new DbBackup();
            $backupEntry->id = 0;
            $backupEntry->manual = $isAuto ? 0 : 1;
            $backupEntry->db = $dbCred->dbname;
            $backupEntry->epoch = $epoch;
            $backupEntry->filename = $filename;
            $backupEntry->size = $filesize;
            $backupEntry->query()->insert();
        } catch (\Exception $e) {
            @unlink($filename . ".sql");
            throw $e;
        }

        $this->print("{green}Success");
    }

    /**
     * @return void
     * @throws AppException
     * @throws \App\Common\Exception\AppDirException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function runSystemCron(): void
    {
        $this->inline("Loading {yellow}{invert} SystemConfig {/} instance from Cache {grey}...{/} ");
        $this->systemConfig = SystemConfig::getInstance(useCache: true);
        $this->print("{green}OK{/}");
        $this->print("");

        // Run the Pruning
        $this->runPurges();

        // Run Database Backups
        $this->runAutoDbBackups();
        $this->runDbBackupsPurges();
        $this->print("");

        // Print Triggered Errors
        $this->printErrors();

        // Cleanup
        $this->aK->db->flushAllQueries();
        $this->aK->errors->flush();
    }

    /**
     * @return void
     * @throws \App\Common\Exception\AppDirException
     * @throws \Comely\Database\Exception\ORM_Exception
     * @throws \Comely\Database\Exception\ORM_ModelQueryException
     * @throws \Comely\Database\Exception\SchemaTableException
     */
    private function runDbBackupsPurges(): void
    {
        if ($this->systemConfig->dbBackupKeepLast < 2) {
            return;
        }

        $this->inline("{yellow}Pruning DB backups{/} ... ");

        $backupsDir = $this->aK->dirs->backups();

        try {
            $dbBackups = DbBackups::Find()->query('WHERE 1 ORDER BY `id` DESC')->all();
        } catch (ORM_ModelNotFoundException) {
            $dbBackups = [];
        }

        $deleted = 0;
        $dbBackups = array_slice($dbBackups, $this->systemConfig->dbBackupKeepLast);
        if ($dbBackups) {
            /** @var DbBackup $dbBackup */
            foreach ($dbBackups as $dbBackup) {
                try {
                    $backupsDir->delete($dbBackup->filename . ".zip");
                } catch (PathException) {
                }

                $dbBackup->query()->delete();
                $deleted++;
            }
        }

        $this->print("{red}{invert} " . $deleted . " {/}");
    }

    /**
     * @return void
     * @throws AppException
     * @throws \App\Common\Exception\AppDirException
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function runAutoDbBackups(): void
    {
        $this->print("");
        $this->inline("{cyan}Auto Database Backups{/} ... ");
        if (!$this->systemConfig->autoDbBackup || $this->systemConfig->autoDbBackupHours < 1) {
            $this->print("{red}Disabled{/}");
            return;
        }

        $timeStamp = time();
        $dbBackupEvery = $this->systemConfig->autoDbBackupHours * 3600;

        try {
            /** @var DbBackup $lastDbBackupOn */
            $lastDbBackupOn = DbBackups::Find()->query('WHERE `manual`=0 ORDER BY `epoch` DESC')->limit(1)->first();
        } catch (ORM_ModelNotFoundException) {
            $lastDbBackupOn = new DbBackup(); // No backups in table, create first one now
            $lastDbBackupOn->epoch = $timeStamp - $dbBackupEvery;
        }

        if (($timeStamp - $lastDbBackupOn->epoch) >= ($dbBackupEvery - 60)) {
            $this->createDbBackup(true, Databases::PRIMARY);
            return;
        }

        $timeUnits = new TimeUnits();
        $timeLeft = $timeUnits->timeToUnits($dbBackupEvery - ($timeStamp - $lastDbBackupOn->epoch));
        $this->print(
            sprintf("in {green}{invert} %d h %d m %s s {/}",
                $timeLeft->hours + ($timeLeft->days * 24),
                $timeLeft->minutes,
                $timeLeft->seconds)
        );
    }

    /**
     * @return void
     * @throws \Comely\Database\Exception\DatabaseException
     */
    private function runPurges(): void
    {
        $db = $this->aK->db->primary();
        $timeStamp = time();

        // Admin Sessions Purge
        $this->inline("Purging {magenta}Administration Sessions{/} ");
        if ($this->systemConfig->adminSessionsPurge > 0) {
            $this->inline(sprintf("older than {green}{invert} %d {/} days:", $this->systemConfig->adminSessionsPurge));
            $query = $db->exec(
                sprintf("DELETE " . "FROM `%s` WHERE `last_used_on`<=?", Sessions::TABLE),
                [$timeStamp - ($this->systemConfig->adminSessionsPurge * 86400)]
            );

            $this->print("\t {cyan}{invert} " . $query->rows() . " {/}.");
        } else {
            $this->print("... {red}Disabled{/}");
        }

        // Admin Logs Purge
        $this->inline("Purging {magenta}Administration Log{/} ");
        if ($this->systemConfig->adminLogsPurge > 0) {
            $this->inline(sprintf("older than {green}{invert} %d {/} days:", $this->systemConfig->adminLogsPurge));
            $query = $db->exec(
                sprintf("DELETE " . "FROM `%s` WHERE `time_stamp`<=?", Logs::TABLE),
                [$timeStamp - ($this->systemConfig->adminLogsPurge * 86400)]
            );

            $this->print("\t {cyan}{invert} " . $query->rows() . " {/}.");
        } else {
            $this->print("... {red}Disabled{/}");
        }

        // Users Logs Purge
        $this->inline("Purging {magenta}Users Log{/} ");
        if ($this->systemConfig->usersLogsPurge > 0) {
            $this->inline(sprintf("older than {green}{invert} %d {/} days:", $this->systemConfig->usersLogsPurge));
            $query = $db->exec(
                sprintf("DELETE " . "FROM `%s` WHERE `time_stamp`<=?", \App\Common\Database\Primary\Users\Logs::TABLE),
                [$timeStamp - ($this->systemConfig->usersLogsPurge * 86400)]
            );

            $this->print("\t {cyan}{invert} " . $query->rows() . " {/}.");
        } else {
            $this->print("... {red}Disabled{/}");
        }

        // Public API Queries and Payloads
        $apiLogsDb = $this->aK->db->apiLogs();
        $this->inline("Purging {magenta}Public API Queries{/} ");
        if ($this->systemConfig->publicAPIQueriesPurge > 0) {
            $this->inline(sprintf("older than {green}{invert} %d {/} days:", $this->systemConfig->publicAPIQueriesPurge));
            $pruneTs = $timeStamp - ($this->systemConfig->publicAPIQueriesPurge * 86400);
            $pruneFromId = $apiLogsDb->fetch(
                sprintf("SELECT " . "* FROM `%s` WHERE `start_on`<=? ORDER BY `id` DESC LIMIT 1", Queries::TABLE),
                [$pruneTs]
            )->row();

            $pruneFromId = intval($pruneFromId["id"] ?? 0);
            if ($pruneFromId) {
                // Delete queries payload
                $delQP = $apiLogsDb->exec(
                    sprintf("DELETE " . "FROM `%s` WHERE `query`<=?", QueriesPayload::TABLE),
                    [$pruneFromId]
                );

                // Delete queries
                $delQ = $apiLogsDb->exec(
                    sprintf("DELETE " . "FROM `%s` WHERE `id`<=?", Queries::TABLE),
                    [$pruneFromId]
                );

                $this->print("\t {cyan}{invert} " . $delQP->rows() . " {/} {yellow}{invert} " . $delQ->rows() . " {/}.");
            } else {
                $this->print("\t {cyan}{invert} 0 {/}.");
            }
        } else {
            $this->print("... {red}Disabled{/}");
        }

        // Public API Sessions
        $this->inline("Purging {magenta}Public API Sessions{/} ");
        if ($this->systemConfig->publicAPISessionsPurge > 0) {
            $this->inline(sprintf("older than {green}{invert} %d {/} days:", $this->systemConfig->publicAPISessionsPurge));
            $query = $db->exec(
                sprintf(
                    "SET FOREIGN_KEY_CHECKS=0; DELETE FROM `%s` WHERE `last_used_on`<=?; SET FOREIGN_KEY_CHECKS=1;",
                    \App\Common\Database\PublicAPI\Sessions::TABLE
                ),
                [$timeStamp - ($this->systemConfig->adminLogsPurge * 86400)]
            );

            $this->print("\t {cyan}{invert} " . $query->rows() . " {/}.");
        } else {
            $this->print("... {red}Disabled{/}");
        }
    }

    /**
     * @return string|null
     */
    public function processInstanceId(): ?string
    {
        return "app_daemon";
    }

    /**
     * @return string|null
     */
    public function semaphoreLockId(): ?string
    {
        return "app_daemon";
    }
}
