<?php
declare(strict_types=1);

namespace App\Common;

use App\Common\DataStore\MailConfig;
use App\Common\DataStore\MailService;
use App\Common\Exception\AppException;
use App\Common\Exception\AppModelNotFoundException;
use Comely\Mailer\Agents\MailGun;
use Comely\Mailer\Agents\SMTP;
use Comely\Mailer\Mailer;
use Comely\Mailer\Templating;

/**
 * Class Emails
 * @package App\Common
 */
class Emails
{
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
    public function __construct(AppKernel $app)
    {
        try {
            $mailConfig = MailConfig::getInstance(true);
        } catch (AppModelNotFoundException) {
            throw new AppException('Cannot instantiate Emails; MailConfig is not set');
        }

        // Setup Mailer
        $this->mailer = new Mailer();
        $this->mailer->sender->name($mailConfig->senderName);
        $this->mailer->sender->email($mailConfig->senderEmail);

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
}
