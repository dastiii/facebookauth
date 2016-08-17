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

namespace Modules\Facebookauth\Mappers;

use stdClass;

class User extends \Ilch\Mapper
{
    /**
     * Checks if the user has a linked facebook account.
     *
     * @return bool
     */
    public function hasLink()
    {
        if (!loggedIn()) {
            return false;
        }

        $userId = currentUser()->getId();

        $result = $this->db()->select()
            ->fields('user_id')
            ->from('users_auth_providers')
            ->where([
                'user_id' => $userId,
                'provider' => 'facebook',
            ])
            ->execute();

        return $result->getNumRows() > 0;
    }

    /**
     * Links a user account with the facebook account.
     *
     * @param stdClass $user facebook user
     *
     * @return bool
     */
    public function link(stdClass $user)
    {
        if (!loggedIn()) {
            return false;
        }

        $result = $this->db()->insert('users_auth_providers', [
            'user_id' => currentUser()->getId(),
            'provider' => 'facebook',
            'identifier' => $user->id,
            'screen_name' => $user->name,
            'created_at' => (new \Ilch\Date('NOW'))->toDb(true),
        ])->execute();

        return true;
    }

    /**
     * Checks if a facebook account is registered.
     *
     * @param stdClass $user
     *
     * @return int|bool
     */
    public function get(stdClass $user)
    {
        $result = $this->db()->select()
            ->fields(['user_id'])
            ->from('users_auth_providers')
            ->where([
                'identifier' => $user->id,
                'provider' => 'facebook',
            ])
            ->execute()
            ->fetchCell('user_id');

        return $result;
    }
}
