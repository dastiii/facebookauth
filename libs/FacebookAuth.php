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

namespace Modules\Facebookauth\Libs;

class FacebookAuth
{
    /**
     * Status if a user denies the app authorization.
     */
    const ERROR_USER_DENIED = 'error.userDenied';

    /**
     * Status if the auth fails (unknown reason).
     */
    const ERROR_AUTH_FAILED = 'error.authFailed';

    /**
     * Status if the csrf token is invalid.
     */
    const ERROR_INVALID_CSRF_TOKEN = 'error.invalidCsrfToken';

    /**
     * The url facebook redirects to upon authorization of your app.
     *
     * @var string
     */
    protected $callbackUrl = null;

    /**
     * Your appId.
     *
     * @var string
     */
    protected $appId = null;

    /**
     * Your appSecret.
     *
     * @var string
     */
    protected $appSecret = null;

    /**
     * Token to prevent CSRF attacks.
     *
     * @var string
     */
    protected $csrfToken;

    /**
     * Error code.
     *
     * @var string|null
     */
    protected $errorCode = null;

    /**
     * Version of Facebooks graph API.
     *
     * @var string
     */
    protected $graphApiVersion;

    /**
     * Permissions to request from the person using your app.
     *
     * @var array
     */
    protected $permissions = [
        'public_profile',
    ];

    /**
     * Construct.
     */
    public function __construct()
    {
        // TODO: Get appId and appSecret (and graphVersion?) from database
        $this->setAppId('1151382428241836');
        $this->setAppSecret('1caf7e02341afbb21c201770895fa43c');
        $this->setGraphApiVersion('v2.7');
    }

    public function redirect($url)
    {
        $this->generateCsrfToken();

        if (is_null($this->getAppId())) {
            throw new \Exception('FacebookAuth: No appId specified.');
        }

        if (is_null($this->getCallbackUrl())) {
            throw new \Exception('FacebookAuth: No callbackUrl specified.');
        }

        $params = [
            'client_id' => $this->getAppId(),
            'state' => $this->getCsrfToken(),
            'scope' => $this->getPermissionsAsString(),
            'redirect_uri' => $this->getCallbackUrl(),
        ];

        header('Location: '.$this->buildUrl($url, $params));
        exit;
    }

    /**
     * Generates a csrf token for the auth dialog.
     *
     * @return string the csrf token
     */
    protected function generateCsrfToken()
    {
        $token = bin2hex(openssl_random_pseudo_bytes(32));

        $_SESSION['facebookauth_csrf']['token'] = $token;
        $_SESSION['facebookauth_csrf']['expires'] = strtotime('+5 minutes');

        return $this->setCsrfToken($token);
    }

    public function evaluateResponse($queryParams)
    {
        $this->checkCsrfToken(array_dot($queryParams, 'state'));

        $code = array_dot($queryParams, 'code');
        $errorReason = array_dot($queryParams, 'error_reason');

        if (!is_null($code) && !$this->hasError()) {
            $this->getAccessToken($code);
        }

        if (!is_null($errorReason) && $errorReason === 'user_denied') {
            $this->setErrorCode(self::ERROR_USER_DENIED);

            return;
        }

        $this->setErrorCode(self::ERROR_AUTH_FAILED);

        return;
    }

    protected function getAccessToken($code)
    {
        $baseUrl = 'https://graph.facebook.com/'.$this->getGraphApiVersion().'/oauth/access_token';
        $urlParams = [
            'client_id' => $this->getAppId(),
            'redirect_uri' => $this->getCallbackUrl(),
            'client_secret' => $this->getAppSecret(),
            'code' => $code,
        ];

        $request = curl_init();

        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($request, CURLOPT_URL, $this->buildUrl($baseUrl, $urlParams));
        curl_setopt($request, CURLOPT_POST, 0);

        // TODO: DEBUG mode!
        curl_setopt($request, CURLOPT_VERBOSE, true);

        $response = curl_exec($request);
    }

    /**
     * Checks if the csrf token matches.
     *
     * @param string $token The csrf token url parameter
     *
     * @return bool
     */
    protected function checkCsrfToken($token)
    {
        $sessionToken = null;
        $sessionExpires = null;

        if (isset($_SESSION['facebookauth_csrf']['token'])) {
            $sessionToken = $_SESSION['facebookauth_csrf']['token'];
            unset($_SESSION['facebookauth_csrf']['token']);
        }

        if (isset($_SESSION['facebookauth_csrf']['expires'])) {
            $sessionExpires = $_SESSION['facebookauth_csrf']['expires'];
            unset($_SESSION['facebookauth_csrf']['expires']);
        }

        if (is_null($token) || is_null($sessionToken) || is_null($sessionExpires)) {
            $this->setErrorCode(self::ERROR_INVALID_CSRF_TOKEN);

            return;
        }

        if ($token === $sessionToken && $sessionExpires >= time()) {
            return;
        }

        $this->setErrorCode(self::ERROR_INVALID_CSRF_TOKEN);

        return;
    }

    protected function buildUrl($baseUrl, $urlParams)
    {
        return $baseUrl.'?'.http_build_query($urlParams);
    }

    /**
     * Get the value of The url facebook redirects to upon authorization of your app.
     *
     * @return string
     */
    public function getCallbackUrl()
    {
        return $this->callbackUrl;
    }

    /**
     * Set the value of The url facebook redirects to upon authorization of your app.
     *
     * @param string callbackUrl
     *
     * @return self
     */
    public function setCallbackUrl($callbackUrl)
    {
        $this->callbackUrl = $callbackUrl;

        return $this;
    }

    /**
     * Get the value of Your appId.
     *
     * @return string
     */
    public function getAppId()
    {
        return $this->appId;
    }

    /**
     * Set the value of Your appId.
     *
     * @param string appId
     *
     * @return self
     */
    public function setAppId($appId)
    {
        $this->appId = $appId;

        return $this;
    }

    /**
     * Get the value of Token to prevent CSRF attacks.
     *
     * @return string
     */
    public function getCsrfToken()
    {
        return $this->csrfToken;
    }

    /**
     * Set the value of Token to prevent CSRF attacks.
     *
     * @param string csrfToken
     *
     * @return self
     */
    public function setCsrfToken($csrfToken)
    {
        $this->csrfToken = $csrfToken;

        return $this;
    }

    /**
     * Get the value of Permissions to request from the person using your app.
     *
     * @return array
     */
    public function getPermissions()
    {
        return $this->permissions;
    }

    /**
     * Set the value of Permissions to request from the person using your app.
     *
     * @param array permissions
     *
     * @return self
     */
    public function setPermissions(array $permissions)
    {
        $this->permissions = $permissions;

        return $this;
    }

    /**
     * Returns the permissions array as a comma separated string.
     *
     * @return string the requested permissions
     */
    public function getPermissionsAsString()
    {
        return implode(',', $this->getPermissions());
    }

    /**
     * Get the value of Error code.
     *
     * @return string
     */
    public function getErrorCode()
    {
        return $this->errorCode;
    }

    /**
     * Set the value of Error code.
     *
     * @param string errorCode
     *
     * @return self
     */
    public function setErrorCode($errorCode)
    {
        $this->errorCode = $errorCode;

        return $this;
    }

    /**
     * Returns whether or not an error occured.
     *
     * @return bool
     */
    public function hasError()
    {
        return !is_null($this->getErrorCode());
    }

    /**
     * Get the value of Your appSecret.
     *
     * @return string
     */
    public function getAppSecret()
    {
        return $this->appSecret;
    }

    /**
     * Set the value of Your appSecret.
     *
     * @param string appSecret
     *
     * @return self
     */
    public function setAppSecret($appSecret)
    {
        $this->appSecret = $appSecret;

        return $this;
    }

    /**
     * Get the value of Version of Facebooks graph API.
     *
     * @return string
     */
    public function getGraphApiVersion()
    {
        return $this->graphApiVersion;
    }

    /**
     * Set the value of Version of Facebooks graph API.
     *
     * @param string graphApiVersion
     *
     * @return self
     */
    public function setGraphApiVersion($graphApiVersion)
    {
        $this->graphApiVersion = $graphApiVersion;

        return $this;
    }
}
