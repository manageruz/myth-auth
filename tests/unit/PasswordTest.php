<?php

use CodeIgniter\Config\Factories;
use CodeIgniter\Test\CIUnitTestCase;
use Myth\Auth\Password;

/**
 * @internal
 */
final class PasswordTest extends CIUnitTestCase
{
    public function testFreshHashDoesNotNeedRehash()
    {
        $config = config('Auth');
        $hash   = Password::hash('secret');

        $this->assertTrue(Password::verify('secret', $hash));

        // Must compare against Config\Auth, not PHP's default options.
        // PHP 8.4 raised the default bcrypt cost to 12, so comparing
        // against the defaults reported every hash as outdated.
        $this->assertFalse(Password::needsRehash($hash, $config->hashAlgorithm));
    }

    public function testNeedsRehashWhenConfiguredCostChanges()
    {
        $hash = Password::hash('secret');

        $config = clone config('Auth');
        $config->hashCost++;
        Factories::injectMock('Config', 'Auth', $config);

        $this->assertTrue(Password::needsRehash($hash, PASSWORD_BCRYPT));
    }

    public function testExplicitOptionsAreRespected()
    {
        $hash = password_hash('secret', PASSWORD_BCRYPT, ['cost' => 11]);

        $this->assertFalse(Password::needsRehash($hash, PASSWORD_BCRYPT, ['cost' => 11]));
        $this->assertTrue(Password::needsRehash($hash, PASSWORD_BCRYPT, ['cost' => 12]));
    }
}
