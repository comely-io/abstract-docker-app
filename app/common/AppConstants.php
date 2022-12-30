<?php
declare(strict_types=1);

namespace App\Common;

/**
 * AppConstants Interface
 */
interface AppConstants
{
    /** @var string App Name, Extending class should change these constant */
    public const NAME = "Comely App Kernel";
    /** string Comely App Kernel Version (Major.Minor.Release-Suffix) */
    public const VERSION = "2022.08";
    /** int Comely App Kernel Version (Major . Minor . Release) */
    public const VERSION_ID = 20220800;
    /** @var int[] */
    public const ROOT_ADMINISTRATORS = [1];
    /** @var string */
    public const ADMIN_API_HEADER_SESS_TOKEN = "admin-sess-token";
    /** @var string */
    public const ADMIN_API_HEADER_CLIENT_SIGN = "admin-signature";
    /** @var string */
    public const PUBLIC_API_HEADER_SESS_TOKEN = "api-token";
    /** @var string */
    public const PUBLIC_API_HEADER_CLIENT_SIGN = "user-signature";
    /** @var string */
    public const PUBLIC_API_HEADER_FINGERPRINT = "browser-fingerprint";
}
