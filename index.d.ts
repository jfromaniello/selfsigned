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
   * @default 2048
   */
  keySize?: number
  /**
   * additional extensions for the certificate
   */
  extensions?: any[];
  /**
   * The signature algorithm: sha256, sha384, sha512 or sha1
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
   * @default 2048
   */
   clientCertificateKeySize?: number
  /**
   * existing key pair to use instead of generating new keys
   */
   keyPair?: {
     privateKey: string
     publicKey: string
   }
}

declare interface GenerateResult {
  private: string
  public: string
  cert: string
  fingerprint: string
  pkcs7?: string
  clientprivate?: string
  clientpublic?: string
  clientcert?: string
  clientpkcs7?: string
}

/**
 * Generate a self-signed certificate (async only)
 *
 * @param attrs Certificate attributes
 * @param opts Generation options
 * @returns Promise that resolves with certificate data
 *
 * @example
 * ```typescript
 * const pems = await generate();
 *
 * const pems = await generate([{ name: 'commonName', value: 'example.com' }]);
 *
 * const pems = await generate(null, {
 *   keySize: 2048,
 *   algorithm: 'sha256'
 * });
 * ```
 */
export declare function generate(
  attrs?: CertificateField[],
  opts?: SelfsignedOptions
): Promise<GenerateResult>
