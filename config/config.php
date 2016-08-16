<?php
/**
 * @copyright Ilch 2.0
 */

namespace Modules\FacebookAuth\Config;

class Config extends \Ilch\Config\Install
{
    public $config = [
        'key' => 'facebookauth',
        'icon_small' => 'fa-facebook',
        'author' => 'Tobias Schwarz',
        'version' => '0.0.1',
        'languages' => [
            'de_DE' => [
                'name' => 'Anmelden mit Facebook',
                'description' => 'Ermöglicht die Anmeldung per Facebook.',
            ],
            'en_EN' => [
                'name' => 'Sign in with Facebook',
                'description' => 'Allows users to sign in through facebook.',
            ],
        ],
    ];

    public function install()
    {
        $this->db()->queryMulti($this->getInstallSql());
    }

    public function getInstallSql()
    {
        return "
            INSERT IGNORE INTO `[prefix]_auth_providers`
                (`key`, `name`, `icon`)
            VALUES
                ('facebook', 'Facebook', 'fa-facebook');

            INSERT INTO `[prefix]_auth_providers_modules`
                (`module`, `provider`, `auth_controller`, `auth_action`,
                `unlink_controller`, `unlink_action`)
            VALUES
                ('facebookauth', 'facebook', 'auth', 'index', 'auth', 'unlink');
        ";
    }

    public function getUpdate()
    {
        //
    }
}
