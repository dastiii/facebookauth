<?php
// COPYRIGHT (c) 2016 Tobias Schwarz
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

/**
 * @copyright Tobias Schwarz
 * @author Tobias Schwarz <github@tobias-schwarz.me>
 * @license MIT
 */

namespace Modules\Facebookauth\Controllers;

use Modules\Facebookauth\Libs\FacebookAuth;
use Modules\Facebookauth\Mappers\User;

class Auth extends \Ilch\Controller\Frontend
{
    public function indexAction()
    {
        if ((new User())->hasLink()) {
            $this->addMessage('facebookauth.alreadyLinked');
            $this->redirect([
                'module' => 'user',
                'controller' => 'panel',
                'action' => 'providers',
            ]);
        }

        $auth = new FacebookAuth();

        $auth->setCallbackUrl($this->getLayout()->getUrl([
            'module' => 'facebookauth',
            'controller' => 'auth',
            'action' => 'callback',
        ]));

        $auth->setPermissions(['public_profile', 'email']);

        $this->redirect($auth->redirectUrl('https://www.facebook.com/dialog/oauth'));
    }

    public function callbackAction()
    {
        $user = new User();

        $auth = new FacebookAuth();

        $auth->setCallbackUrl($this->getLayout()->getUrl([
            'module' => 'facebookauth',
            'controller' => 'auth',
            'action' => 'callback',
        ]));

        $auth->performAuthentication($this->getRequest()->getQuery());

        if ($auth->hasError()) {
            throw new \Exception('There was an error: '.$auth->getErrorCode());
        }

        if (loggedIn() && $user->link($auth->getUser())) {
            //TODO: Save access_token
            $this->addMessage('facebookauth.accountsLinkedSuccessfully');
            $this->redirect([
                'module' => 'user',
                'controller' => 'panel',
                'action' => 'providers',
            ]);
        }

        $authUserId = $user->get($auth->getUser());

        if (!is_null($authUserId) && $authUserId !== false) {
            $_SESSION['user_id'] = $authUserId;

            $this->addMessage('facebookauth.welcome');
            $this->redirect([
                'module' => 'user',
                'controller' => 'panel',
                'action' => 'index',
            ]);
        }

        //TODO: User registration
    }
}
