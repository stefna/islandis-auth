<?php declare(strict_types=1);

namespace Islandis\Tests;

use Islandis\Exception\CertificateError;
use Islandis\Exception\InvalidResponse;
use Islandis\Exception\ValidationFailure;
use Islandis\Exception\XmlError;
use Islandis\Verifier;
use PHPUnit\Framework\TestCase;

final class VerifierTest extends TestCase
{
	public function testEmptyToken(): void
	{
		$verifier = new Verifier('audience', FrozenClock::live());

		$this->expectException(\InvalidArgumentException::class);

		$verifier->verify('');
	}

	public function testXmlError(): void
	{
		$this->expectException(XmlError::class);

		$token = 'test';

		$verifier = new Verifier('audience', FrozenClock::live());
		$verifier->verify($token);
	}

	public function testCertNotFound(): void
	{
		$this->expectException(CertificateError::class);

		new Verifier('audience', FrozenClock::live(), 'resources');
	}

	public function testInvalidAudience(): void
	{
		$this->expectException(ValidationFailure::class);
		$this->expectExceptionMessage('Invalid audience expected "audience" got "login.advania.is"');

		$verifier = new Verifier('audience', new FrozenClock(new \DateTimeImmutable(
			'2014-01-17T15:16:52.1745763Z'
		)));
		$verifier->verify(base64_encode(file_get_contents(__DIR__ . '/resources/response.xml')));
	}

	public function testNotWithinTimeframe(): void
	{
		$this->expectException(InvalidResponse::class);
		$this->expectExceptionMessage('Response is not within specified timeframe');

		$verifier = new Verifier('login.advania.is', new FrozenClock(new \DateTimeImmutable(
			'2015-01-01T00:00:00Z0000'
		)));
		$verifier->verify(base64_encode(file_get_contents(__DIR__ . '/resources/response.xml')));
	}

	public function testValidResponse(): void
	{
		$this->markTestSkipped('Don\'t have a valid response to test against');

		$audienceUrl = '???';
		$clock =  new FrozenClock(new \DateTimeImmutable(
			'2021-01-12T14:54:22.7537164Z'
		));
		$userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88'
			. ' Safari/537.36';

		$verifier = new Verifier($audienceUrl, $clock);
		$verifier->setUserAgent($userAgent);

		$token = base64_encode(file_get_contents(__DIR__ . '/resources/valid_response.xml'));

		self::assertTrue($verifier->verify($token));
	}

	public function testXmlWrapping(): void
	{
		self::expectException(CertificateError::class);

		$audienceUrl = 'login.advania.is';
		$clock =  new FrozenClock(new \DateTimeImmutable(
			'2014-01-17T15:20:22.7537164Z'
		));
		$userAgent = 'Mozilla/5.0 (Windows NT6.1; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0';

		$verifier = new Verifier($audienceUrl, $clock);
		$verifier->setUserAgent($userAgent);

		$token = base64_encode(file_get_contents(__DIR__ . '/resources/response-wrapping.xml'));

		$verifier->verify($token);
	}

	public function testGetUserAgentFallback(): void
	{
		$this->expectException(ValidationFailure::class);
		$this->expectExceptionMessage('User-agent does not match');
		$audienceUrl = 'login.advania.is';
		$clock =  new FrozenClock(new \DateTimeImmutable(
			'2014-01-17T15:20:22.7537164Z'
		));
		$verifier = new Verifier($audienceUrl, $clock);
		$verifier->verify(base64_encode(file_get_contents(__DIR__ . '/resources/response.xml')));
	}
}
