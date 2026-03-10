<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Hvatum\OpenIDConnect\Client\OptionProvider\OpenIDConnectOptionProvider;
use Hvatum\OpenIDConnect\Client\Tool\ClientAssertionTrait;
use Hvatum\OpenIDConnect\Client\Tool\DPopTrait;
use Hvatum\OpenIDConnect\Client\Tool\PARTrait;
use Hvatum\OpenIDConnect\Client\Tool\WellKnownConfigTrait;
use Hvatum\OpenIDConnect\Client\Cache\FilesystemCache;
use Hvatum\OpenIDConnect\Client\Validator\NonceChecker;
use Psr\SimpleCache\CacheInterface;

/**
 * Generic OpenID Connect Provider
 *
 * Implements OAuth 2.0 Authorization Code Flow with:
 * - Well-known configuration discovery (auto-configuration)
 * - PAR (Pushed Authorization Requests) - RFC 9126
 * - PKCE (Proof Key for Code Exchange) - RFC 7636
 * - Private_key_jwt client authentication - RFC 7523
 * - DPoP (Demonstrating Proof of Possession) - RFC 9449
 * - OpenID Connect (ID token validation, nonces)
 * - Client Credentials flow for machine-to-machine API access
 *
 * Works with any OpenID Connect compliant server.
 */
class OpenIDConnectProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;
    use WellKnownConfigTrait;
    use PARTrait;
    use ClientAssertionTrait;
    use DPopTrait;

    public const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'sub';

    /**
     * Scope delimiter (space-separated as per OAuth 2.0 spec)
     */
    public const SCOPE_DELIMITER = ' ';

    /**
     * Client assertion JWT expiration time in seconds
     */
    public const CLIENT_ASSERTION_TTL = 120;

    /**
     * Default scopes for OpenID Connect
     */
    public const DEFAULT_SCOPES = [
        'openid',
    ];

    /**
     * JWKS cache TTL in seconds (1 hour)
     */
    public const JWKS_CACHE_TTL = 3600;

    /**
     * Clock skew leeway for JWT validation in seconds
     */
    public const CLOCK_SKEW_LEEWAY = 60;

    /**
     * Configured issuer identifier (from constructor option)
     */
    protected string $expectedIssuer;

    /**
     * Dynamically loaded endpoints from well-known config
     */
    protected ?string $authorizationUrl = null;
    protected ?string $tokenUrl = null;
    protected ?string $userInfoUrl = null;
    protected ?string $parUrl = null;
    protected ?string $revocationUrl = null;
    protected ?string $endSessionUrl = null;
    protected ?string $jwksUrl = null;
    protected ?string $issuerUrl = null;

    /**
     * Current nonce for ID token validation
     */
    protected ?string $nonce = null;

    /**
     * Callback issuer for RFC 9207 validation
     */
    protected ?string $callbackIssuer = null;

    /**
     * Whether the AS advertises RFC 9207 issuer response parameter support
     * (authorization_response_iss_parameter_supported in discovery)
     */
    protected bool $issuerResponseParameterSupported = false;

    /**
     * Algorithms the server supports for signing ID tokens.
     * REQUIRED per OIDC Discovery §3; defaults to ['RS256'] if absent.
     * @var array<string>
     */
    protected array $idTokenSigningAlgValuesSupported = ['RS256'];

    /**
     * Algorithms the server supports for token endpoint auth signing.
     * OPTIONAL per OIDC Discovery; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $tokenEndpointAuthSigningAlgValuesSupported = null;

    /**
     * Algorithms the server supports for DPoP proof signing (RFC 9449).
     * OPTIONAL; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $dpopSigningAlgValuesSupported = null;

    /**
     * Authentication methods the server supports at the token endpoint.
     * OPTIONAL per OIDC Discovery; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $tokenEndpointAuthMethodsSupported = null;

    /**
     * Code challenge methods the server supports for PKCE (RFC 7636).
     * OPTIONAL; null means not advertised.
     * @var array<string>|null
     */
    protected ?array $codeChallengeMethodsSupported = null;

    /**
     * Whether the server requires Pushed Authorization Requests (RFC 9126).
     */
    protected bool $requirePushedAuthorizationRequests = false;

    /**
     * Whether to enforce RFC 9207 issuer identification validation.
     * When true (default), if the AS advertises support, callbacks missing
     * the iss parameter will be rejected.
     */
    protected bool $enforceIssuerIdentification = true;

    /**
     * ID token from last token response
     */
    protected ?string $idToken = null;
    protected ?array $validatedIdTokenClaims = null;

    /**
     * JWKS cache TTL in seconds (configurable via options)
     */
    protected int $jwksCacheTtl = self::JWKS_CACHE_TTL;

    /**
     * Last token request params (for DPoP nonce retry)
     */
    protected ?array $lastTokenParams = null;

    /**
     * PSR-3 Logger instance
     */
    protected LoggerInterface $logger;

    /**
     * Initialize OpenID Connect provider
     *
     * Required options:
     * - issuer: Issuer identifier URL (e.g., 'https://idp.example.com')
     *
     * Optional options:
     * - wellKnownUrl: Override the auto-derived well-known URL (for non-standard paths)
     * - privateKeyPath: Path to private key for client assertion (RFC 7523)
     * - keyId: Key ID for client assertion
     * - dpopPrivateKeyPath: Path to DPoP private key (RFC 9449)
     * - dpopPublicKeyPath: Path to DPoP public key (RFC 9449)
     * - cacheDir: Custom cache directory (used when no PSR-16 cache is provided)
     * - wellKnownCacheTtl: Discovery metadata cache TTL in seconds (non-negative integer)
     * - jwksCacheTtl: JWKS cache TTL in seconds (non-negative integer)
     *
     * @param array $options Provider configuration options
     * @param array $collaborators Optional collaborators (httpClient, requestFactory, logger, cache)
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (empty($options['issuer'])) {
            throw new \InvalidArgumentException('issuer is required for OpenID Connect discovery');
        }

        // Initialize logger (use NullLogger if not provided)
        $this->logger = $collaborators['logger'] ?? new NullLogger();

        parent::__construct($options, $collaborators);

        // Use custom option provider that delegates body building to this provider
        $this->setOptionProvider(new OpenIDConnectOptionProvider(
            fn(array $params) => $this->getAccessTokenBody($params)
        ));

        // Initialize PSR-16 cache (use provided, or default to filesystem)
        if (isset($collaborators['cache']) && $collaborators['cache'] instanceof CacheInterface) {
            $this->cache = $collaborators['cache'];
        } else {
            $cacheDir = $options['cacheDir'] ?? $this->getDefaultCacheDir();
            $this->cache = new FilesystemCache($cacheDir);
        }

        $this->wellKnownCacheTtl = $this->resolveCacheTtlOption(
            $options,
            'wellKnownCacheTtl',
            $this->wellKnownCacheTtl
        );
        $this->jwksCacheTtl = $this->resolveCacheTtlOption(
            $options,
            'jwksCacheTtl',
            static::JWKS_CACHE_TTL
        );

        // Derive well-known URL from issuer, or use explicit override
        $this->expectedIssuer = $options['issuer'];
        $wellKnownUrl = $options['wellKnownUrl']
            ?? rtrim($this->expectedIssuer, '/') . '/.well-known/openid-configuration';
        $this->loadWellKnownConfiguration($wellKnownUrl, $this->expectedIssuer);

        $this->logger->debug('OpenID Connect provider initialized', [
            'issuer' => $this->issuerUrl,
            'par_enabled' => $this->parUrl !== null,
        ]);

        // Optional: Disable strict RFC 9207 enforcement
        if (isset($options['enforceIssuerIdentification'])) {
            $this->enforceIssuerIdentification = (bool) $options['enforceIssuerIdentification'];
        }

        // Optional: Initialize client assertion (private_key_jwt)
        if (!empty($options['privateKeyPath'])) {
            $this->initializeClientAssertion(
                $options['privateKeyPath'],
                $options['keyId'] ?? null
            );
        }

        // Optional: Initialize DPoP (public key is derived from private key if not provided)
        if (!empty($options['dpopPrivateKeyPath'])) {
            $this->initializeDPoP(
                $options['dpopPrivateKeyPath'],
                $options['dpopPublicKeyPath'] ?? null
            );
        }
    }

    /**
     * Get default cache directory with per-user namespace.
     */
    protected function getDefaultCacheDir(): string
    {
        $identifier = null;

        if (function_exists('posix_geteuid')) {
            $uid = posix_geteuid();
            if (is_int($uid) && $uid >= 0) {
                $identifier = 'uid:' . $uid;
            }
        }

        if ($identifier === null) {
            $user = getenv('USER') ?: getenv('USERNAME');
            if (is_string($user) && $user !== '') {
                $identifier = 'user:' . $user;
            }
        }

        $namespace = $identifier !== null ? hash('sha256', $identifier) : 'default';
        return sys_get_temp_dir() . '/oauth2-oidc/' . $namespace;
    }

    /**
     * Resolve and validate cache TTL option.
     *
     * @param array<string,mixed> $options
     */
    protected function resolveCacheTtlOption(array $options, string $optionName, int $default): int
    {
        if (!array_key_exists($optionName, $options)) {
            return $default;
        }

        $value = $options[$optionName];
        if (!is_int($value) || $value < 0) {
            throw new \InvalidArgumentException(
                sprintf('%s must be a non-negative integer number of seconds', $optionName)
            );
        }

        return $value;
    }

    /**
     * Get the base authorization URL
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        $this->ensureEndpointsLoaded();
        return $this->authorizationUrl;
    }

    /**
     * Get the base access token URL
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        $this->ensureEndpointsLoaded();
        return $this->tokenUrl;
    }

    /**
     * Get the user info URL
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        $this->ensureEndpointsLoaded();
        if ($this->userInfoUrl === null) {
            throw new \RuntimeException(
                'UserInfo endpoint not available. The authorization server discovery response '
                . 'did not include a userinfo_endpoint.'
            );
        }
        return $this->userInfoUrl;
    }

    /**
     * Get an access token from the authorization code.
     *
     * Automatically extracts the RFC 9207 `iss` parameter from options
     * so callers can pass it alongside `code`:
     *
     *     $token = $provider->getAccessToken('authorization_code', [
     *         'code' => $_GET['code'],
     *         'iss'  => $_GET['iss'] ?? null,
     *     ]);
     *
     * @param mixed $grant
     * @param array $options
     * @return AccessToken
     */
    public function getAccessToken($grant, array $options = [])
    {
        // Extract RFC 9207 iss parameter before passing to parent
        if (array_key_exists('iss', $options)) {
            $this->setCallbackIssuer($options['iss']);
            unset($options['iss']);
        }

        return parent::getAccessToken($grant, $options);
    }

    /**
     * Add DPoP proof when fetching access tokens
     *
     * @param array $params
     * @return \Psr\Http\Message\RequestInterface
     */
    protected function getAccessTokenRequest(array $params)
    {
        // Store params for potential DPoP nonce retry
        $this->lastTokenParams = $params;

        $request = parent::getAccessTokenRequest($params);

        if ($this->hasDPoP()) {
            $proof = $this->createDPopProof('POST', $request->getUri());
            $request = $request->withHeader('DPoP', $proof);
            $this->logger->debug('DPoP proof attached to token request', [
                'uri' => (string) $request->getUri(),
                'has_nonce' => $this->getDPopNonce() !== null,
            ]);
        }

        return $request;
    }

    /**
     * Get the audience URL for client assertion JWTs.
     *
     * Default: token endpoint URL per RFC 7523 §3.
     * Override in subclasses if the authorization server requires a different audience
     * (e.g. the issuer URL instead of the token endpoint).
     *
     * See
     * https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/06/
     * section 3
     *
     * @return string
     */
    protected function getClientAssertionAudience(): string
    {
        return $this->tokenUrl;
    }

    /**
     * Build access token request body
     *
     * Adds client assertion, DPoP thumbprint, authorization_details (RFC 9396),
     * and handles formatting.
     *
     * @param array $params
     * @return string
     */
    protected function getAccessTokenBody(array $params): string
    {
        // Validate token endpoint auth method against server's advertised list
        if ($this->tokenEndpointAuthMethodsSupported !== null) {
            $method = $this->hasClientAssertion() ? 'private_key_jwt' : 'client_secret_post';
            if (!in_array($method, $this->tokenEndpointAuthMethodsSupported, true)) {
                throw new \RuntimeException(
                    sprintf(
                        'Client uses %s authentication but the authorization server does not support it. Supported: %s',
                        $method,
                        implode(', ', $this->tokenEndpointAuthMethodsSupported)
                    )
                );
            }
        }

        // RFC 9396: authorization_details is sent as a JSON string parameter.
        $params = $this->normalizeAuthorizationDetailsParameter($params);
        $authorizationDetails = $this->decodeAuthorizationDetailsValue($params['authorization_details'] ?? null);

        // Add client assertion (private_key_jwt) if configured
        if ($this->hasClientAssertion()) {
            $previousAuthorizationDetails = $this->clientAuthorizationDetails;
            $assertionDetails = $this->getAuthorizationDetailsForClientAssertion($params, $authorizationDetails);
            if ($assertionDetails !== null) {
                $this->setClientAuthorizationDetails($assertionDetails);

                if (!$this->shouldSendAuthorizationDetailsInTokenRequestBody($params, $authorizationDetails)) {
                    unset($params['authorization_details']);
                }
            }

            try {
                $assertion = $this->createClientAssertion($this->getClientAssertionAudience());
                $params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
                $params['client_assertion'] = $assertion;
                unset($params['client_secret']);
            } finally {
                $this->setClientAuthorizationDetails($previousAuthorizationDetails);
            }
        }

        // Add DPoP key thumbprint for token binding
        if ($this->hasDPoP() && !isset($params['dpop_jkt'])) {
            $params['dpop_jkt'] = $this->getDPopJwkThumbprint();
        }

        // Join scope array with separator (parent doesn't handle this)
        if (isset($params['scope']) && is_array($params['scope'])) {
            $params['scope'] = implode($this->getScopeSeparator(), $params['scope']);
        }

        return $this->buildQueryString($params);
    }

    /**
     * Normalize authorization_details parameter to a JSON string (RFC 9396).
     *
     * @param array $params
     * @return array
     */
    protected function normalizeAuthorizationDetailsParameter(array $params): array
    {
        if (isset($params['authorization_details']) && !is_string($params['authorization_details'])) {
            try {
                $params['authorization_details'] = json_encode(
                    $params['authorization_details'],
                    JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
                );
            } catch (\JsonException $e) {
                throw new \RuntimeException(
                    'Failed to JSON-encode authorization_details: ' . $e->getMessage(),
                    0,
                    $e
                );
            }
        }

        return $params;
    }

    /**
     * Decode authorization_details value into array form for internal extension hooks.
     *
     * @param mixed $authorizationDetails
     * @return array|null
     */
    protected function decodeAuthorizationDetailsValue($authorizationDetails): ?array
    {
        if (is_array($authorizationDetails)) {
            return $authorizationDetails;
        }

        if (is_string($authorizationDetails)) {
            $decoded = json_decode($authorizationDetails, true);
            return is_array($decoded) ? $decoded : null;
        }

        return null;
    }

    /**
     * Extension hook for profile-specific claim embedding in client assertions.
     * Default keeps RFC 9396 behavior and does not copy authorization_details into JWT claims.
     *
     * @param array $params
     * @param array|null $authorizationDetails Decoded authorization_details if available
     * @return array|null Details to pass to setClientAuthorizationDetails(), or null for no embedding
     */
    protected function getAuthorizationDetailsForClientAssertion(array $params, ?array $authorizationDetails): ?array
    {
        return null;
    }

    /**
     * Extension hook to optionally omit authorization_details from the token request body
     * when getAuthorizationDetailsForClientAssertion() returns details.
     *
     * @param array $params
     * @param array|null $authorizationDetails
     * @return bool
     */
    protected function shouldSendAuthorizationDetailsInTokenRequestBody(array $params, ?array $authorizationDetails): bool
    {
        return true;
    }

    /**
     * Get default scopes
     *
     * @return array
     */
    protected function getDefaultScopes(): array
    {
        return static::DEFAULT_SCOPES;
    }

    /**
     * Get scope separator
     *
     * @return string
     */
    protected function getScopeSeparator(): string
    {
        return static::SCOPE_DELIMITER;
    }

    /**
     * Enforce PKCE with S256
     */
    protected function getPkceMethod()
    {
        return static::PKCE_METHOD_S256;
    }

    /**
     * Check token response for errors
     *
     * @param ResponseInterface $response
     * @param array|string $data
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        // Extract DPoP nonce from any response (before potential throw)
        $this->extractDPopNonce($response);

        if ($response->getStatusCode() >= 400) {
            $this->logger->warning('Token request failed', [
                'status' => $response->getStatusCode(),
                'error' => is_array($data) ? ($data['error'] ?? 'unknown') : 'unknown',
            ]);
            throw new IdentityProviderException(
                $data['error_description'] ?? $data['error'] ?? $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }

        if (is_array($data) && isset($data['error'])) {
            $this->logger->warning('Token response contains error', [
                'error' => $data['error'],
            ]);
            throw new IdentityProviderException(
                $data['error_description'] ?? $data['error'],
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Create resource owner from successful response
     *
     * @param array $response
     * @param AccessToken $token
     * @return OpenIDConnectResourceOwner
     * @throws IdentityProviderException If ID token validation fails or UserInfo sub does not match
     */
    protected function createResourceOwner(array $response, AccessToken $token): OpenIDConnectResourceOwner
    {
        // Merge ID token claims with userinfo response (OIDC Core §5.3.2)
        // Userinfo takes precedence — it has richer identity data.
        // Filter out transport claims from ID token that shouldn't pollute the resource owner.
        if ($this->idToken !== null) {
            $idTokenClaims = $this->getValidatedIdTokenClaims();

            // OIDC Core §5.3.2: sub in UserInfo MUST exactly match ID token sub.
            if (isset($response['sub']) && $response['sub'] !== $idTokenClaims['sub']) {
                throw new IdentityProviderException(
                    'UserInfo sub claim does not match ID token sub claim',
                    0,
                    null
                );
            }

            $transportClaims = ['at_hash', 'c_hash', 'nonce', 'auth_time', 'azp', 'acr', 'amr'];
            $identityClaims = array_diff_key($idTokenClaims, array_flip($transportClaims));
            $response = array_merge($identityClaims, $response);
        }

        return new OpenIDConnectResourceOwner($response);
    }

    /**
     * Fetch resource owner details from userinfo endpoint
     *
     * @param AccessToken $token
     * @return array
     * @throws IdentityProviderException
     */
    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $url = $this->getResourceOwnerDetailsUrl($token);

        // Userinfo endpoint uses Bearer authentication
        $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new \UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }

    /**
     * Get authorization parameters including nonce and PKCE
     *
     * @param array $options
     * @return array
     */
    protected function getAuthorizationParameters(array $options): array
    {
        // Remove Google-specific parameter that the base library adds by default.
        // OIDC uses 'prompt' instead (none, login, consent, select_account)
        $params = parent::getAuthorizationParameters($options);

        unset($params['approval_prompt']);

        // Generate and store nonce for ID token validation
        $this->nonce = $this->generateNonce();
        $params['nonce'] = $this->nonce;

        // RFC 9396: authorization_details in authorization and PAR requests is JSON.
        $params = $this->normalizeAuthorizationDetailsParameter($params);

        // Validate PKCE method against server's advertised list
        if ($this->codeChallengeMethodsSupported !== null
            && !in_array('S256', $this->codeChallengeMethodsSupported, true)
        ) {
            throw new \RuntimeException(
                'PKCE method S256 is not supported by the authorization server. Supported: '
                . implode(', ', $this->codeChallengeMethodsSupported)
            );
        }

        // If PAR is enabled, push the authorization request
        if ($this->usePAR()) {
            $this->logger->debug('Using PAR (Pushed Authorization Request)');
            $requestUri = $this->pushAuthorizationRequest($params);
            // Replace all params with just client_id and request_uri
            return [
                'client_id' => $this->clientId,
                'request_uri' => $requestUri,
            ];
        }

        return $params;
    }

    /**
     * Parse the access token response
     *
     * @param ResponseInterface $response
     * @return array
     */
    protected function parseResponse(ResponseInterface $response): array
    {
        $parsed = parent::parseResponse($response);

        // Parent can return string/null for non-JSON responses
        if (!is_array($parsed)) {
            throw new \UnexpectedValueException(
                'Invalid response from Authorization Server. Expected JSON object, got: ' .
                (is_string($parsed) ? substr($parsed, 0, 100) : gettype($parsed))
            );
        }

        // Store ID token if present
        if (isset($parsed['id_token'])) {
            $this->idToken = $parsed['id_token'];
            $this->validatedIdTokenClaims = null;
        }

        return $parsed;
    }

    /**
     * Get parsed response with DPoP nonce retry support
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @return mixed
     * @throws IdentityProviderException
     */
    public function getParsedResponse(\Psr\Http\Message\RequestInterface $request)
    {
        try {
            return parent::getParsedResponse($request);
        } catch (IdentityProviderException $e) {
            // Only retry for token endpoint with DPoP nonce errors
            $isTokenRequest = $this->lastTokenParams !== null
                && ((string) $request->getUri()) === $this->tokenUrl;

            if ($isTokenRequest && $this->hasDPoP() && $this->isDPopNonceError($e) && $this->getDPopNonce() !== null) {
                // Nonce was extracted in getResponse(), rebuild request and retry
                $this->logger->debug('Retrying token request with server-provided DPoP nonce');
                $retryRequest = $this->getAccessTokenRequest($this->lastTokenParams);
                $this->lastTokenParams = null; // Prevent infinite retry
                return parent::getParsedResponse($retryRequest);
            }
            throw $e;
        } catch (\UnexpectedValueException $e) {
            // Log raw response for debugging non-JSON responses
            $this->logger->error('Request failed with non-JSON response', [
                'exception' => $e->getMessage(),
            ]);
            throw $e;
        }
    }

    /**
     * Extract DPoP nonce from any response (success or error)
     *
     * Called from checkResponse() before throwing, so it works
     * with any PSR-18 HTTP client.
     *
     * @param ResponseInterface $response
     */
    protected function extractDPopNonce(ResponseInterface $response): void
    {
        if ($this->hasDPoP()) {
            $nonceHeader = $response->getHeader('DPoP-Nonce');
            if (!empty($nonceHeader)) {
                $this->setDPopNonce($nonceHeader[0]);
                $this->logger->debug('Received DPoP nonce from server response');
            }
        }
    }

    /**
     * Check if exception is a DPoP nonce error per RFC 9449
     *
     * Per RFC 9449 Section 8.2, when the server requires a nonce:
     * - HTTP status: 400
     * - Error code: "use_dpop_nonce"
     * - DPoP-Nonce header contains the nonce to use
     *
     * @param IdentityProviderException $e
     * @return bool
     */
    protected function isDPopNonceError(IdentityProviderException $e): bool
    {
        // checkResponse() sets the exception message from the parsed error field,
        // so use_dpop_nonce will appear in the message if the server sent it.
        if (strpos(strtolower($e->getMessage()), 'use_dpop_nonce') !== false) {
            return true;
        }

        // Fallback: check the response body directly (safe stream read)
        $response = $e->getResponseBody();
        if ($response instanceof ResponseInterface) {
            $stream = $response->getBody();
            try {
                $stream->rewind();
                $body = (string) $stream;
                $data = json_decode($body, true);
                if (is_array($data) && ($data['error'] ?? null) === 'use_dpop_nonce') {
                    return true;
                }
            } catch (\Throwable $ignored) {
                // Stream may not be seekable; message check above is sufficient
            }
        }

        return false;
    }

    /**
     * Get the stored ID token from last authentication
     *
     * @return string|null
     * @throws IdentityProviderException If the stored ID token fails validation
     */
    public function getIdToken(): ?string
    {
        if ($this->idToken !== null) {
            // Ensure callers do not consume an unvalidated ID token.
            // Throws on error
            $this->getValidatedIdTokenClaims();
        }

        // Return all the original token, not just the validated claims
        return $this->idToken;
    }

    /**
     * Validate and cache claims for the stored ID token.
     *
     * @return array|null
     * @throws IdentityProviderException If the stored ID token fails validation
     */
    protected function getValidatedIdTokenClaims(): ?array
    {
        if ($this->idToken === null) {
            return null;
        }

        if ($this->validatedIdTokenClaims === null) {
            $this->validatedIdTokenClaims = $this->validateIdToken($this->idToken);
        }

        return $this->validatedIdTokenClaims;
    }

    /**
     * Get the nonce used in the authorization request
     *
     * @return string|null
     * @codeCoverageIgnore
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * Set nonce (useful when restoring from session)
     *
     * @param string $nonce
     */
    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
        $this->validatedIdTokenClaims = null;
    }

    /**
     * Get the callback issuer (RFC 9207)
     *
     * @return string|null
     * @codeCoverageIgnore
     */
    public function getCallbackIssuer(): ?string
    {
        return $this->callbackIssuer;
    }

    /**
     * Set callback issuer from authorization response (RFC 9207)
     *
     * Automatically set when passing 'iss' in getAccessToken() options.
     * Can also be called manually if needed before getIdToken()/validateIdToken().
     *
     * @param string|null $issuer
     */
    public function setCallbackIssuer(?string $issuer): void
    {
        $this->callbackIssuer = $issuer;
        $this->validatedIdTokenClaims = null;
    }

    /**
     * Generate a cryptographically secure nonce
     *
     * @return string
     */
    protected function generateNonce(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Get the issuer URL from well-known configuration
     *
     * @return string|null
     * @codeCoverageIgnore
     */
    public function getIssuerUrl(): ?string
    {
        return $this->issuerUrl;
    }

    /**
     * Get the end session endpoint from well-known configuration
     * (RP-Initiated Logout 1.0)
     *
     * @return string|null
     * @codeCoverageIgnore
     */
    public function getEndSessionEndpoint(): ?string
    {
        return $this->endSessionUrl;
    }

    /**
     * Validate ID token
     *
     * @param string $idToken The ID token JWT
     * @param string|null $nonce Expected nonce value
     * @param string|null $callbackIssuer Issuer from authorization callback (RFC 9207)
     * @return array Validated claims from ID token
     * @throws IdentityProviderException
     */
    public function validateIdToken(string $idToken, ?string $nonce = null, ?string $callbackIssuer = null): array
    {
        $nonce = $nonce ?? $this->nonce;
        $callbackIssuer = $callbackIssuer ?? $this->callbackIssuer;
        $this->ensureEndpointsLoaded();

        $this->logger->debug('Validating ID token', [
            'has_nonce' => $nonce !== null,
            'has_callback_issuer' => $callbackIssuer !== null,
        ]);

        // RFC 9207 - Authorization Server Issuer Identification
        // When the AS advertises support, reject callbacks that are missing the iss parameter
        if ($callbackIssuer === null
            && $this->issuerResponseParameterSupported
            && $this->enforceIssuerIdentification
        ) {
            $this->logger->warning('RFC 9207: AS supports issuer identification but callback is missing iss parameter');
            throw new IdentityProviderException(
                'Authorization response is missing the iss parameter. '
                . 'The authorization server advertises authorization_response_iss_parameter_supported. '
                . 'This may indicate a mix-up attack (RFC 9207).',
                0,
                null
            );
        }

        // Validate callback issuer parameter against expected issuer
        // This protects against mix-up attacks when using multiple identity providers
        if ($callbackIssuer !== null && $callbackIssuer !== $this->issuerUrl) {
            $this->logger->warning('Potential mix-up attack: issuer mismatch in callback', [
                'callback_issuer' => $callbackIssuer,
                'expected_issuer' => $this->issuerUrl,
            ]);
            throw new IdentityProviderException(
                sprintf(
                    'Issuer mismatch: callback iss parameter "%s" does not match expected issuer "%s"',
                    $callbackIssuer,
                    $this->issuerUrl
                ),
                0,
                null
            );
        }

        if ($this->jwksUrl === null) {
            throw new IdentityProviderException('JWKS URL not available for ID token validation', 0, null);
        }

        // Parse with serializer (avoid hand-rolled JWT decoding).
        $serializer = new CompactSerializer();
        try {
            $jws = $serializer->unserialize($idToken);
            $header = $jws->getSignature(0)->getProtectedHeader();
        } catch (\Throwable $e) {
            throw new IdentityProviderException('Invalid ID token format', 0, null);
        }

        // Algorithms this library can verify (prevent algorithm confusion attacks)
        $librarySupported = [
            'ES256', 'ES384', 'ES512',
            'RS256', 'RS384', 'RS512',
            'PS256', 'PS384', 'PS512',
        ];

        // Intersect with what the server advertises (from discovery)
        $allowedAlgorithms = array_values(array_intersect(
            $librarySupported,
            $this->idTokenSigningAlgValuesSupported
        ));

        if (empty($allowedAlgorithms)) {
            throw new IdentityProviderException(
                'No mutually supported ID token signing algorithms. '
                . 'Server supports: ' . implode(', ', $this->idTokenSigningAlgValuesSupported)
                . '. Library supports: ' . implode(', ', $librarySupported),
                0,
                null
            );
        }

        $tokenAlg = $header['alg'] ?? null;

        if (!is_string($tokenAlg) || !in_array($tokenAlg, $allowedAlgorithms, true)) {
            $this->logger->warning('ID token uses disallowed algorithm', [
                'algorithm' => $tokenAlg,
                'allowed' => $allowedAlgorithms,
            ]);
            throw new IdentityProviderException(
                "Invalid ID token algorithm: '{$tokenAlg}'. Allowed: " . implode(', ', $allowedAlgorithms),
                0,
                null
            );
        }

        try {
            // Build AlgorithmManager with only mutually supported algorithms
            $algorithmMap = [
                'ES256' => ES256::class, 'ES384' => ES384::class, 'ES512' => ES512::class,
                'RS256' => RS256::class, 'RS384' => RS384::class, 'RS512' => RS512::class,
                'PS256' => PS256::class, 'PS384' => PS384::class, 'PS512' => PS512::class,
            ];
            $algorithms = [];
            foreach ($allowedAlgorithms as $alg) {
                $algorithms[] = new $algorithmMap[$alg]();
            }
            $algorithmManager = new AlgorithmManager($algorithms);
            $jwsVerifier = new JWSVerifier($algorithmManager);
            $jwkSet = JWKSet::createFromKeyData($this->getJwks());

            if (!$jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0)) {
                // Retry once with fresh JWKS in case the key set rotated recently.
                $jwkSet = JWKSet::createFromKeyData($this->getJwks(true));
                if (!$jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0)) {
                    throw new \RuntimeException('Signature verification failed');
                }
            }

            $decoded = json_decode($jws->getPayload(), true);
            if (!is_array($decoded)) {
                throw new \RuntimeException('Invalid payload');
            }

            // Validate registered claims using claim checkers with clock skew
            // PSR-20 clock required by web-token v4 time-based checkers
            $clock = new class implements \Psr\Clock\ClockInterface {
                public function now(): \DateTimeImmutable
                {
                    return new \DateTimeImmutable();
                }
            };
            $claimCheckerManager = new ClaimCheckerManager([
                new IssuerChecker([$this->issuerUrl]),
                new AudienceChecker($this->clientId),
                new ExpirationTimeChecker(static::CLOCK_SKEW_LEEWAY, false, $clock),
                new NotBeforeChecker(static::CLOCK_SKEW_LEEWAY, false, $clock),
                new IssuedAtChecker(static::CLOCK_SKEW_LEEWAY, false, $clock),
                new NonceChecker($nonce),
            ]);

            /* Validate claims (throws on failure)
             * claimsChecker can return claims, but will
             * only return claims that are explicitly validated.
             *
             * We keep $decoded and use that as return value
             * in order to keep other claims as well
             */

            // Mandatory claims per OIDC Core; add nonce when one was sent (§3.1.3.7)
            $mandatoryClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
            if ($nonce !== null) {
                $mandatoryClaims[] = 'nonce';
            }
            $claimCheckerManager->check($decoded, $mandatoryClaims);
        } catch (MissingMandatoryClaimException $e) {
            $this->logger->warning('ID token missing mandatory claims', [
                'reason' => $e->getMessage(),
                'claims' => $e->getClaims(),
            ]);
            throw new IdentityProviderException(
                'ID token claim validation failed: ' . $e->getMessage(),
                0,
                null
            );
        } catch (InvalidClaimException $e) {
            $this->logger->warning('ID token claim validation failed', [
                'reason' => $e->getMessage(),
                'claim' => method_exists($e, 'getClaim') ? $e->getClaim() : 'unknown',
            ]);
            throw new IdentityProviderException(
                'ID token claim validation failed: ' . $e->getMessage(),
                0,
                null
            );
        } catch (\Throwable $e) {
            $this->logger->warning('ID token validation failed', [
                'reason' => $e->getMessage(),
            ]);
            throw new IdentityProviderException(
                'Failed to validate ID token: ' . $e->getMessage(),
                0,
                null
            );
        }

        // Verify sub claim is present (OIDC Core Section 2)
        if (!isset($decoded['sub']) || !is_string($decoded['sub'])) {
            throw new IdentityProviderException('ID token missing required sub claim', 0, null);
        }

        // Verify azp when multiple audiences are present
        $audience = $decoded['aud'] ?? [];
        $audList = is_array($audience) ? $audience : [$audience];
        if (count($audList) > 1 && ($decoded['azp'] ?? null) !== $this->clientId) {
            throw new IdentityProviderException('ID token azp mismatch', 0, null);
        }

        $this->logger->debug('ID token validated successfully', [
            'sub' => $decoded['sub'],
            'iss' => $decoded['iss'] ?? 'unknown',
        ]);

        return $decoded;
    }

    /**
     * Fetch JWKS with PSR-16 caching
     *
     * @return array
     * @throws IdentityProviderException
     */
    protected function getJwks(bool $forceRefresh = false): array
    {
        // Check PSR-16 cache
        $cacheKey = 'jwks_' . md5($this->jwksUrl ?? '');
        if (!$forceRefresh && $this->cache !== null) {
            $cached = $this->cache->get($cacheKey);
            if (is_array($cached) && isset($cached['keys']) && is_array($cached['keys'])) {
                $this->logger->debug('Using cached JWKS', [
                    'key_count' => count($cached['keys']),
                ]);
                return $cached;
            }
        }

        try {
            $request = $this->getRequest('GET', $this->jwksUrl);
            $response = $this->getHttpClient()->send($request);

            if ($response->getStatusCode() !== 200) {
                throw new IdentityProviderException(
                    'Failed to fetch JWKS',
                    $response->getStatusCode(),
                    $response
                );
            }

            $body = (string)$response->getBody();
            $data = json_decode($body, true);
            if (!is_array($data) || !isset($data['keys']) || !is_array($data['keys'])) {
                throw new IdentityProviderException('Invalid JWKS response format', 0, $response);
            }

            $this->cache?->set($cacheKey, $data, $this->jwksCacheTtl);

            $this->logger->debug('Fetched fresh JWKS', [
                'key_count' => count($data['keys']),
            ]);

            return $data;
        } catch (IdentityProviderException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new IdentityProviderException(
                'Failed to fetch JWKS: ' . $e->getMessage(),
                0,
                null
            );
        }
    }

    /**
     * Ensure endpoints are loaded from well-known config
     *
     * @throws \RuntimeException
     */
    protected function ensureEndpointsLoaded(): void
    {
        if ($this->authorizationUrl === null) {
            throw new \RuntimeException(
                'Endpoints not loaded. Provide issuer in options or call loadWellKnownConfiguration()'
            );
        }
    }

    /**
     * Determine if PAR should be used
     * PAR is used when the endpoint is available
     *
     * @return bool
     */
    protected function usePAR(): bool
    {
        if ($this->requirePushedAuthorizationRequests && $this->parUrl === null) {
            throw new \RuntimeException(
                'The authorization server requires Pushed Authorization Requests (PAR) '
                . 'but no pushed_authorization_request_endpoint was found in the discovery document'
            );
        }

        return $this->parUrl !== null;
    }
}
