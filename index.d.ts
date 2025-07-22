declare enum ASN1Class {
    UNIVERSAL = 0x00,
    APPLICATION = 0x40,
    CONTEXT_SPECIFIC = 0x80,
    PRIVATE = 0xc0,
}

interface CertificateFieldOptions {
    name?: string | undefined;
    type?: string | undefined;
    shortName?: string | undefined;
}

interface CertificateField extends CertificateFieldOptions {
    valueConstructed?: boolean | undefined;
    valueTagClass?: ASN1Class | undefined;
    value?: any[] | string | undefined;
    extensions?: any[] | undefined;
}

declare interface SelfsignedOptions {
  /**
   * The number of days before expiration
   *
   * @default 365 */
  days?: number

  /**
   * The date before which the certificate should not be valid
   *
   * @default now */
  notBeforeDate?: Date

  /**
   * the size for the private key in bits
   * @default 1024
   */
  keySize?: number
  /**
   * additional extensions for the certificate
   */
  extensions?: any[];
  /**
   * The signature algorithm sha256 or sha1
   * @default "sha1"
   */
  algorithm?: string
  /**
   * include PKCS#7 as part of the output
   * @default false
   */
  pkcs7?: boolean
  /**
   * generate client cert signed by the original key
   * @default false
   */
  clientCertificate?: boolean
  /**
   * client certificate's common name
   * @default "John Doe jdoe123"
   */
  clientCertificateCN?: string
  /**
   * the size for the client private key in bits
   * @default 1024
   */
   clientCertificateKeySize?: number
}

declare interface GenerateResult {
  private: string
  public: string
  cert: string
  fingerprint: string
}

export declare function generate(
  attrs?: CertificateField[],
  opts?: SelfsignedOptions
): GenerateResult

export declare function generate(
  attrs?: CertificateField[],
  opts?: SelfsignedOptions,
  /** Optional callback, if not provided the generation is synchronous */
  done?: (err: undefined | Error, result: GenerateResult) => any
): void
