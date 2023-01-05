<?php
declare(strict_types=1);

namespace App\Common;

use App\Common\DataStore\MailConfig;
use App\Common\DataStore\MailService;
use App\Common\Exception\AppException;
use App\Common\Exception\AppModelNotFoundException;
use App\Common\Kernel\ErrorHandler\Errors;
use App\Common\Misc\QueuedMail;
use Comely\Mailer\Agents\MailGun;
use Comely\Mailer\Agents\SMTP;
use Comely\Mailer\Exception\MailerException;
use Comely\Mailer\Mailer;
use Comely\Mailer\Message;
use Comely\Mailer\Templating;

/**
 * Class Emails
 * @package App\Common
 */
class Emails
{
    /** @var \App\Common\DataStore\MailService */
    public readonly MailService $service;
    /** @var \Comely\Mailer\Mailer */
    public readonly Mailer $mailer;
    /** @var \Comely\Mailer\Templating */
    public readonly Templating $templating;

    /**
     * @param \App\Common\AppKernel $app
     * @throws \App\Common\Exception\AppDirException
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Filesystem\Exception\PathException
     * @throws \Comely\Mailer\Exception\MailerException
     */
    public function __construct(private readonly AppKernel $app)
    {
        try {
            $mailConfig = MailConfig::getInstance(true);
            $this->service = $mailConfig->service;
        } catch (AppModelNotFoundException) {
            throw new AppException('Cannot instantiate Emails; MailConfig is not set');
        }

        // Setup Mailer
        $this->mailer = new Mailer();
        $this->mailer->sender->name($mailConfig->senderName ?? $this->app->config->public->title);
        $this->mailer->sender->email($mailConfig->senderEmail ?? $this->app->config->public->email);

        // Configure Delivery Agent
        if ($mailConfig->service === MailService::MAILGUN) {
            if (!$mailConfig->mgApiDomain || !$mailConfig->mgApiKey || !is_bool($mailConfig->mgEurope)) {
                throw new AppException('Incomplete MailGun configuration');
            }

            $mailGun = new MailGun(
                $mailConfig->mgApiDomain,
                $mailConfig->mgApiKey,
                $mailConfig->mgEurope,
                $app->dirs->storage()->suffix("/data/mozilla/ca_root.pem"),
                $mailConfig->timeOut + 1,
                ($mailConfig->timeOut * 2) + 1
            );

            $this->mailer->setAgent($mailGun);
        } elseif ($mailConfig->service === MailService::SMTP) {
            if (!$mailConfig->hostname || !$mailConfig->port) {
                throw new AppException('Incomplete SMTP configuration');
            }

            $this->mailer->setAgent((new SMTP(
                $mailConfig->hostname,
                $mailConfig->port,
                $mailConfig->timeOut
            )));
        }


        // Templating
        $this->templating = new Templating($this->mailer, $app->dirs->emails()->dir("/messages", true)->path());
        $default = new Templating\Template(
            $this->templating,
            "default",
            $app->dirs->emails()->suffix("/templates/default/template.html"),
        );

        $this->templating->registerTemplate($default);

        // Base data bind
        $this->templating->set("config", $app->config->public);
    }

    /**
     * @param string $name
     * @param string $subject
     * @param string|null $preHeader
     * @param string|null $template
     * @return \Comely\Mailer\Templating\TemplatedEmail
     * @throws \Comely\Mailer\Exception\DataBindException
     * @throws \Comely\Mailer\Exception\TemplatingException
     */
    public function create(string $name, string $subject, ?string $preHeader = null, ?string $template = "default"): Templating\TemplatedEmail
    {
        $email = $this->templating->template($template)->useBody($name, $subject);
        $email->set("preHeader", $preHeader ?? $subject);
        return $email;
    }

    /**
     * @param \Comely\Mailer\Message $message
     * @param string $recipient
     * @param bool $dispatch
     * @return \App\Common\Misc\QueuedMail|null
     * @throws \App\Common\Exception\AppException
     * @throws \Comely\Database\Exception\DatabaseException
     * @throws \Comely\Mailer\Exception\EmailMessageException
     */
    public function queueDispatch(Message $message, string $recipient, bool $dispatch = true): ?QueuedMail
    {
        if ($this->service === MailService::DISABLED) {
            return null;
        }

        if ($dispatch && $this->service === MailService::PAUSED) {
            $dispatch = false;
        }

        $compiledMime = $message->compile();
        $compiledLen = strlen($compiledMime->compiled);
        if ($compiledLen > (5 * 1048576)) {
            throw new AppException('E-mail compiled MIME exceeds limit of 5MB');
        }

        $queued = new QueuedMail();
        $queued->id = 0;
        $queued->status = "queued";
        $queued->email = trim($recipient);
        $queued->subject = $message->subject;
        $queued->set("blob", $compiledMime->compiled);
        $queued->addedOn = time();
        $queued->attempts = 0;
        $queued->query()->insert();
        $queued->id = $this->app->db->primary()->lastInsertId();

        if ($dispatch) {
            $queued->attempts++;

            try {
                $this->mailer->send($message, $recipient);
                $queued->status = "sent";
                $queued->sentOn = $queued->addedOn;
                $queued->set("blob", null);
            } catch (MailerException $e) {
                $queued->error = trim(substr(Errors::Exception2String($e), 0, 255));
                $queued->lastAttempt = $queued->addedOn;
            }

            $queued->query()->where("id", $queued->id)->update();
        }

        return $queued;
    }
}
