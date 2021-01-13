<?php declare(strict_types=1);

namespace Islandis;

use DOMNode;
use DOMDocument;
use DOMXPath;
use Exception;
use Islandis\Exception\CertificateError;
use Islandis\Exception\InvalidResponse;
use Islandis\Exception\ValidationFailure;
use Islandis\Exception\XmlError;
use phpseclib3\File\X509;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

final class Verifier
{
	/** @var DOMDocument|null */
	private $xml;
	/** @var string */
	private $myCertPem;
	/** @var string */
	private $trausturBunadurPem;
	/** @var string */
	private $audienceUrl;
	/** @var Clock */
	private $clock;

	public function __construct(string $audienceUrl, ?string $certificateDir = null)
	{
		$this->clock = Clock::live();
		if ($certificateDir === null) {
			$certificateDir = $this->getDefaultCertificateFolder();
		}
		$this->myCertPem = $certificateDir . DIRECTORY_SEPARATOR . 'mycert.pem';
		$this->trausturBunadurPem = $certificateDir . DIRECTORY_SEPARATOR . 'Traustur_bunadur.pem';

		if (!file_exists($this->trausturBunadurPem)) {
			throw CertificateError::notFoundInDirectory($certificateDir);
		}
		$this->audienceUrl = $audienceUrl;
	}

	public function setClock(Clock $clock): void
	{
		$this->clock = $clock;
	}

	protected function getDefaultCertificateFolder(): string
	{
		return \dirname(__DIR__) . DIRECTORY_SEPARATOR . 'certificates';
	}

	public function verify(string $token): bool
	{
		if (!$token) {
			throw new \InvalidArgumentException('Can\'t verify empty token');
		}

		$this->xml = new DOMDocument();
		$this->xml->loadXML(base64_decode($token));

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
		}
		catch (\Exception $e) {
			throw ValidationFailure::reference($e);
		}

		$this->verifyAudience($this->xml);
		$this->verifyDate($this->xml);

		$objKey = $objXMLSecDSig->locateKey();
		if (!$objKey) {
			throw ValidationFailure::keyNotFound();
		}
		$key = null;
		$objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
		if (!$objKeyInfo) {
			throw ValidationFailure::keyInfoNotFound();
		}

		$this->verifyCert($objKeyInfo);

		if (!$objKeyInfo->key && empty($key)) {
			$objKey->loadKey($this->myCertPem, true);
		}
		if (!$objXMLSecDSig->verify($objKey)) {
			throw CertificateError::signatureInvalid();
		}

		$this->checkUserAgent($this->xml, $this->getUserAgent());

		return true;
	}

	public function getAttribute(string $needle): ?string
	{
		if (!$this->xml) {
			throw XmlError::notLoaded();
		}

		$searchNode = $this->xml->getElementsByTagName('Attribute');
		/** @var \DOMElement $attribute */
		foreach ($searchNode as $attribute) {
			$friendly = $attribute->getAttribute('FriendlyName');
			if ($friendly === $needle) {
				return $attribute->nodeValue;
			}
		}

		return null;
	}

	private function verifyDate(DOMDocument $doc): bool
	{
		/** @var \DOMElement|null $conditions */
		$conditions = $this->queryDocument($doc, ['/assertion:Assertion', '/assertion:Conditions']);
		if (!$conditions) {
			throw InvalidResponse::missingData('Conditions');
		}

		$start = $conditions->getAttribute('NotBefore');
		$end = $conditions->getAttribute('NotOnOrAfter');
		if (!$start || !$end) {
			throw InvalidResponse::missingData('NotBefore', 'NotOnOrAfter');
		}

		date_default_timezone_set('Atlantic/Reykjavik');
		$startTime = strtotime($start);
		$endTime = strtotime($end);
		if (!\is_int($startTime) || !\is_int($endTime)) {
			throw InvalidResponse::dateInvalid();
		}
		$now = $this->clock->getTimestamp();
		$inSpan = $startTime < $now && $now < $endTime;
		if (!$inSpan) {
			throw InvalidResponse::notWithinTimeframe();
		}
		return true;
	}

	private function verifyCert(XMLSecurityKey $objKeyInfo): bool
	{
		$leaf = new X509();
		if (!$leaf->loadX509($objKeyInfo->getX509Certificate())) {
			throw CertificateError::readError();
		}
		if (!$leaf->loadCA((string)file_get_contents($this->trausturBunadurPem))) {
			throw CertificateError::readError();
		}

		date_default_timezone_set('Atlantic/Reykjavik');
		if (!$leaf->validateDate($this->clock->getDateTime())) {
			throw CertificateError::expired();
		}

		if ($leaf->getSubjectDNProp('serialNumber')[0] !== '6503760649') {
			throw CertificateError::invalidSubject($leaf->getSubjectDNProp('serialNumber')[0]);
		}

		if ($leaf->getIssuerDNProp('commonName')[0] !== 'Traustur bunadur') {
			throw CertificateError::invalidIssuer($leaf->getIssuerDNProp('commonName')[0] ?? '');
		}

		if (!$leaf->validateSignature()) {
			throw CertificateError::signatureInvalid();
		}

		return true;
	}

	private function checkUserAgent(DOMDocument $xmlDoc, string $ua): void
	{
		if ($xmlDoc !== null) {
			$searchNode = $xmlDoc->getElementsByTagName('Attribute');
			foreach ($searchNode as $attribute) {
				$friendly = $attribute->getAttribute('FriendlyName');
				if (($friendly === 'NotandaStrengur') && $attribute->nodeValue !== $ua) {
					throw ValidationFailure::userAgent();
				}
			}
		}
	}

	private function getUserAgent(): string
	{
		$useragent = '';
		if (!empty($_SERVER['HTTP_USER_AGENT'])) {
			$useragent = $_SERVER['HTTP_USER_AGENT'];
		}

		return $useragent;
	}

	/**
	 * @param string[] $fields
	 */
	private function queryDocument(DOMDocument $doc, array $fields): ?DOMNode
	{
		try {
			$xpath = new DOMXPath($doc);
			$xpath->registerNamespace('assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
			$nodeset = $xpath->query('./' . implode('', $fields), $doc);
			return $nodeset ? $nodeset->item(0) : null;
		}
		catch (Exception $e) {
			throw XmlError::unknown($e);
		}
	}

	private function verifyAudience(DOMDocument $doc): bool
	{
		$audience = $this->queryDocument($doc, [
			'/assertion:Assertion',
			'/assertion:Conditions',
			'/assertion:AudienceRestriction',
			'/assertion:Audience',
		]);

		if (!$audience || $audience->textContent !== $this->audienceUrl) {
			throw ValidationFailure::invalidAudience($audience ? $audience->textContent : '', $this->audienceUrl);
		}

		return true;
	}
}
