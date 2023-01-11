<?php declare(strict_types=1);

namespace Islandis\Exception;

final class XmlError extends \DomainException implements ResponseError
{
	public static function unknown(\Exception $e): self
	{
		return new self('Unknown error while reading xml', 1, $e);
	}

	public static function missingSignature(): self
	{
		return new self('Cannot locate Signature Node');
	}

	public static function notLoaded(): self
	{
		return new self('No xml loaded to read from');
	}

	public static function libXML(false|\LibXMLError $error): self
	{
		return new self($error ? $error->message : 'Unknown error while parsing xml');
	}
}
