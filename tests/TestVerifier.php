<?php declare(strict_types=1);

namespace Islandis\Tests;

use Islandis\Clock;
use Islandis\Exception\CertificateError;
use Islandis\Exception\InvalidResponse;
use Islandis\Exception\ValidationFailure;
use Islandis\Exception\XmlError;
use Islandis\Verifier;
use PHPUnit\Framework\TestCase;

final class TestVerifier extends TestCase
{
	public function testEmptyToken(): void
	{
		$verifier = new Verifier('audience');

		$this->expectException(\InvalidArgumentException::class);

		$verifier->verify('');
	}

	public function testXmlError(): void
	{
		$this->expectException(XmlError::class);

		$token = 'test';

		$verifier = new Verifier('audience');
		$verifier->verify($token);
	}

	public function testCertNotFound(): void
	{
		$this->expectException(CertificateError::class);

		new Verifier('audience', 'resources');
	}

	public function testInvalidAudience(): void
	{
		$this->expectException(ValidationFailure::class);
		$this->expectExceptionMessage('Invalid audience expected "audience" got "login.advania.is"');

		$verifier = new Verifier('audience');
		$verifier->verify(base64_encode(file_get_contents(__DIR__ . '/resources/response.xml')));
	}

	public function testNotWithinTimeframe(): void
	{
		$this->expectException(InvalidResponse::class);
		$this->expectExceptionMessage('Response is not within specified timeframe');

		$verifier = new Verifier('login.advania.is');
		$verifier->setClock(Clock::fixed('2015-01-01T00:00:00Z00:00'));
		$verifier->verify(base64_encode(file_get_contents(__DIR__ . '/resources/response.xml')));
	}

	public function testValidResponse(): void
	{
		$audienceUrl = 'www.press.is';
		$clock = Clock::fixed('2021-01-12T14:54:22.7537164Z');
		$userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88'
			. ' Safari/537.36';

		$verifier = new Verifier($audienceUrl);
		$verifier->setClock($clock);
		$verifier->setUserAgent($userAgent);

		$token = base64_encode(file_get_contents(__DIR__ . '/resources/valid_response.xml'));

		self::assertTrue($verifier->verify($token));
	}
}
