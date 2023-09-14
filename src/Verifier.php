<?php declare(strict_types=1);

namespace Islandis;

use DOMNode;
use DOMDocument;
use DOMXPath;
use Exception;
use Islandis\Exception\AuthenticateError;
use Islandis\Exception\CertificateError;
use Islandis\Exception\InvalidResponse;
use Islandis\Exception\ValidationFailure;
use Islandis\Exception\XmlError;
use phpseclib3\File\X509;
use Psr\Clock\ClockInterface;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

final class Verifier implements VerifierInterface
{
	private const INTERMEDIATE_COMMON_NAME = 'Fullgilt audkenni';

	private ?DOMDocument $xml;
	private string $myCertPem;
	private string $intermediateCert;
	private string $userAgent;
	private ?XMLSecurityKey $objKeyInfo;
	private XMLSecurityDSig $objXMLSecDSig;
	private DOMNode $objDSig;

	public function __construct(
		private readonly string $audienceUrl,
		private readonly ClockInterface $clock,
		?string $certificateDir = null,
	) {
		if ($certificateDir === null) {
			$certificateDir = $this->getDefaultCertificateFolder();
		}
		$this->myCertPem = $certificateDir . DIRECTORY_SEPARATOR . 'mycert.pem';
		$this->intermediateCert = $certificateDir . DIRECTORY_SEPARATOR . 'Milliskilriki.cer';

		if (!file_exists($this->intermediateCert)) {
			throw CertificateError::notFoundInDirectory($certificateDir);
		}
	}

	public function setUserAgent(string $agent): void
	{
		$this->userAgent = $agent;
	}

	/**
	 * @throws AuthenticateError
	 */
	public function verify(string $token): bool
	{
		if (!$token) {
			throw new \InvalidArgumentException('Can\'t verify empty token');
		}

		$this->loadXml($token);

		$this->verifyDate();
		$this->verifyAudience();
		$this->verifyUserAgent();
		$this->verifyReference();
		$this->verifySignature();
		$this->verifyCertificate();

		return true;
	}

	public function getAttribute(string $needle): ?string
	{
		$node = $this->queryDocument([
			'/protocol:Response',
			'/assertion:Assertion',
			'//assertion:Attribute[@Name="' . $needle . '"]',
			'/assertion:AttributeValue',
		]);

		return $node?->nodeValue;
	}

	private function getDefaultCertificateFolder(): string
	{
		return \dirname(__DIR__) . DIRECTORY_SEPARATOR . 'certificates';
	}

	private function loadXml(string $token): void
	{
		// Avoid warnings
		$previous = libxml_use_internal_errors(true);
		$this->xml = new DOMDocument();
		if (!$this->xml->loadXML(base64_decode($token))) {
			throw XmlError::libXML(libxml_get_last_error());
		}
		libxml_use_internal_errors($previous);
	}

	private function getUserAgent(): string
	{
		if (isset($this->userAgent)) {
			return $this->userAgent;
		}

		$useragent = '';
		if (!empty($_SERVER['HTTP_USER_AGENT'])) {
			$useragent = $_SERVER['HTTP_USER_AGENT'];
		}

		return $useragent;
	}

	private function verifyUserAgent(): void
	{
		// todo throw on missing useragent
		if ($this->getAttribute('UserAgent') !== $this->getUserAgent()) {
			throw ValidationFailure::userAgent();
		}
	}

	private function verifyDate(): void
	{
		/** @var \DOMElement|null $conditions */
		$conditions = $this->queryDocument(['/protocol:Response', '/assertion:Assertion', '/assertion:Conditions']);
		if (!$conditions) {
			throw InvalidResponse::missingData('Conditions');
		}

		$start = $conditions->getAttribute('NotBefore');
		$end = $conditions->getAttribute('NotOnOrAfter');
		if (!$start || !$end) {
			throw InvalidResponse::missingData('NotBefore', 'NotOnOrAfter');
		}

		date_default_timezone_set('Atlantic/Reykjavik');
		$startTime = new \DateTimeImmutable($start);
		$endTime = new \DateTimeImmutable($end);
		$now = $this->clock->now();
		$inSpan = $startTime < $now && $now < $endTime;
		if (!$inSpan) {
			throw InvalidResponse::notWithinTimeframe();
		}
	}

	private function verifyCertificate(): void
	{
		if (!$this->objKeyInfo) {
			throw ValidationFailure::keyInfoNotFound();
		}
		$leaf = new X509();
		if (!$leaf->loadX509($this->objKeyInfo->getX509Certificate())) {
			throw CertificateError::readError();
		}
		if (!$leaf->loadCA((string)file_get_contents($this->intermediateCert))) {
			throw CertificateError::readError();
		}

		date_default_timezone_set('Atlantic/Reykjavik');
		if (!$leaf->validateDate($this->clock->now())) {
			throw CertificateError::expired();
		}

		if ($leaf->getSubjectDNProp('serialNumber')[0] !== '6503760649') {
			throw CertificateError::invalidSubject($leaf->getSubjectDNProp('serialNumber')[0]);
		}

		if ($leaf->getIssuerDNProp('commonName')[0] !== self::INTERMEDIATE_COMMON_NAME) {
			throw CertificateError::invalidIssuer($leaf->getIssuerDNProp('commonName')[0] ?? '');
		}

		if (!$leaf->validateSignature()) {
			throw CertificateError::signatureInvalid();
		}
	}

	private function verifyAudience(): void
	{
		$audience = $this->queryDocument([
			'/protocol:Response',
			'/assertion:Assertion',
			'/assertion:Conditions',
			'/assertion:AudienceRestriction',
			'/assertion:Audience',
		]);

		if (!$audience || $audience->textContent !== $this->audienceUrl) {
			throw ValidationFailure::invalidAudience($audience ? $audience->textContent : '', $this->audienceUrl);
		}
	}

	private function verifySignature(): void
	{
		$objKey = $this->objXMLSecDSig->locateKey();
		if (!$objKey) {
			throw ValidationFailure::keyNotFound();
		}
		$this->objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $this->objDSig);
		if (!$this->objKeyInfo) {
			throw ValidationFailure::keyInfoNotFound();
		}
		if (!$this->objKeyInfo->key) {
			$objKey->loadKey($this->myCertPem, true);
		}
		if (!$this->objXMLSecDSig->verify($objKey)) {
			throw CertificateError::signatureInvalid();
		}
	}

	private function verifyReference(): void
	{
		if (!$this->xml) {
			throw XmlError::notLoaded();
		}
		$objXMLSecDSig = new XMLSecurityDSig();
		$objDSig = $objXMLSecDSig->locateSignature($this->xml);

		if ($objDSig === null) {
			throw XmlError::missingSignature();
		}

		$objXMLSecDSig->canonicalizeSignedInfo();
		$objXMLSecDSig->idKeys = ['ID'];
		$objXMLSecDSig->idNS = [
			'wsu' => 'http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
		];
		try {
			$objXMLSecDSig->validateReference();

			$this->objXMLSecDSig = $objXMLSecDSig;
			$this->objDSig = $objDSig;
		}
		catch (\Exception $e) {
			throw ValidationFailure::reference($e);
		}
	}

	/**
	 * @param string[] $fields
	 */
	private function queryDocument(array $fields): ?DOMNode
	{
		if (!$this->xml) {
			throw XmlError::notLoaded();
		}

		try {
			$xpath = new DOMXPath($this->xml);
			$xpath->registerNamespace('assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
			$xpath->registerNamespace('protocol', 'urn:oasis:names:tc:SAML:2.0:protocol');
			$nodeset = $xpath->query(implode('', $fields), $this->xml);
			return $nodeset ? $nodeset->item(0) : null;
		}
		catch (Exception $e) {
			throw XmlError::unknown($e);
		}
	}
}
