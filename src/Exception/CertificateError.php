<?php declare(strict_types=1);

namespace Islandis\Exception;

final class CertificateError extends \RuntimeException implements AuthenticateError
{
	public static function notFoundInDirectory(string $dir): self
	{
		return new self('Cannot find TrausturBunadur.pem in ' . $dir);
	}

	public static function expired(): self
	{
		return new self('Certificate expired or not valid yet');
	}

	public static function readError(string $msg = null): self
	{
		return new self($msg ?? 'Failed to read certificate');
	}

	public static function invalidCA(): self
	{
		return new self('Not correct CA');
	}

	public static function invalidIssuer(string $issuer = ''): self
	{
		if ($issuer) {
			return new self('Invalid issuer: "' . $issuer . '"');
		}
		return new self('Invalid issuer');
	}

	public static function invalidSubject(string $kennitala): self
	{
		return new self('Invalid subject: "' . $kennitala . '"');
	}

	public static function signatureInvalid(): self
	{
		return new self('Signature invalid!');
	}

	public static function parseError(): self
	{
		return new self('Failed to parse certificate');
	}
}
