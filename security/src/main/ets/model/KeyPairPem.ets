export class KeyPairPem {
  constructor(priKey?: string, pubKey?: string) {
    this.priKey = priKey
    this.pubKey = pubKey
  }

  priKey?: string
  pubKey?: string
}