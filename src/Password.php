<?php

namespace Myth\Auth;

/**
 * Class Password
 */
class Password
{
    /**
     * @param string $password Password
     */
    public static function hash(string $password): string
    {
        $config = config('Auth');

        return password_hash(
            self::preparePassword($password),
            $config->hashAlgorithm,
            self::hashOptions($config->hashAlgorithm),
        );
    }

    /**
     * @param string $password Password
     * @param string $hash     Hash
     */
    public static function verify(string $password, string $hash): bool
    {
        return password_verify(self::preparePassword($password), $hash);
    }

    /**
     * Checks whether a hash was made with other settings than the current
     * ones. Without $options it compares against the options from
     * Config\Auth that hash() uses, not against PHP's defaults (PHP 8.4
     * raised the default bcrypt cost from 10 to 12, which made every
     * hash look outdated).
     *
     * @param string     $hash    Hash
     * @param int|string $algo    Hash algorithm
     * @param array      $options Options
     */
    public static function needsRehash(string $hash, $algo, array $options = []): bool
    {
        if ($options === []) {
            $options = self::hashOptions($algo);
        }

        return password_needs_rehash($hash, $algo, $options);
    }

    /**
     * Returns the password_hash() options from Config\Auth for an algorithm.
     *
     * @param int|string|null $algo Hash algorithm
     */
    protected static function hashOptions($algo): array
    {
        $config = config('Auth');

        if (
            (defined('PASSWORD_ARGON2I') && $algo === PASSWORD_ARGON2I)
            || (defined('PASSWORD_ARGON2ID') && $algo === PASSWORD_ARGON2ID)
        ) {
            return [
                'memory_cost' => $config->hashMemoryCost,
                'time_cost'   => $config->hashTimeCost,
                'threads'     => $config->hashThreads,
            ];
        }

        return [
            'cost' => $config->hashCost,
        ];
    }

    /**
     * @param string $password Password
     */
    protected static function preparePassword(string $password): string
    {
        return base64_encode(hash('sha384', $password, true));
    }
}
