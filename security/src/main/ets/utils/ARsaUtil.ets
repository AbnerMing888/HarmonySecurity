import util from '@ohos.util';
import cryptoFramework from '@ohos.security.cryptoFramework';
import buffer from '@ohos.buffer';

/**
 * AUTHOR:AbnerMing
 * DATE:2024/11/21
 * INTRODUCE:非对称加密
 * */
export class ARsaUtil {
  /*
* Author:AbnerMing
* Describe:私有化构造器
*/
  private constructor() {
  }

  /*
* Author:AbnerMing
* Describe:提供一个外部可访问的的静态方法
*/
  public static getInstance() {
    if (!ARsaUtil.rsaUtil) {
      ARsaUtil.rsaUtil = new ARsaUtil()
    }
    return ARsaUtil.rsaUtil
  }

  private static rsaUtil: ARsaUtil

  /*
* Author:AbnerMing
* Describe:解密内容，异步,私钥解密
*/
  async decryptPriKeyContent(content: string, privateKey: string): Promise<string> {
    return this.decryptContent(content, undefined, privateKey)
  }

  /*
* Author:AbnerMing
* Describe:解密内容，同步,私钥解密
*/
  decryptPriKeyContentSync(content: string, privateKey: string): string {
    return this.decryptContentSync(content, undefined, privateKey)
  }

  /*
* Author:AbnerMing
* Describe:解密内容，异步,公私钥解密
*/
  private async decryptContent(content: string, publicKey?: string, privateKey?: string): Promise<string> {
    let keyPair = await this.getKeyPair(publicKey, privateKey);
    // 创建 Cipher对象
    let decoder = cryptoFramework.createCipher('RSA1024|PKCS1')
    await decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE,
      publicKey != undefined ? keyPair.pubKey : keyPair.priKey, null)
    let unit = await new util.Base64Helper().decode(content)
    let cipherText: cryptoFramework.DataBlob = { data: unit };
    // // 传入明文，获取加密后的数据
    let encryptBlob = await decoder.doFinal(cipherText);
    // // 返回加密后的字符串
    let decryptString = buffer.from(encryptBlob.data).toString('utf-8')
    return decryptString;
  }

  /*
* Author:AbnerMing
* Describe:解密内容，同步,公私钥解密
*/
  private decryptContentSync(content: string, publicKey?: string, privateKey?: string): string {
    let keyPair = this.getKeyPairSync(publicKey, privateKey)
    // 创建 Cipher对象
    let decoder = cryptoFramework.createCipher('RSA1024|PKCS1')
    decoder.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, publicKey != undefined ? keyPair.pubKey : keyPair.priKey,
      null)
    let unit = new util.Base64Helper().decodeSync(content)
    let cipherText: cryptoFramework.DataBlob = { data: unit }
    // // 传入明文，获取加密后的数据
    let encryptBlob = decoder.doFinalSync(cipherText)
    // // 返回加密后的字符串
    let decryptString = buffer.from(encryptBlob.data).toString('utf-8')
    return decryptString
  }

  /*
* Author:AbnerMing
* Describe:加密内容，异步,公钥加密
*/
  async encryptPubKeyContent(content: string, publicKey: string): Promise<string> {
    return this.encryptContent(content, publicKey, undefined)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，同步,公钥加密
*/
  encryptPubKeyContentSync(content: string, publicKey: string): string {
    return this.encryptContentSync(content, publicKey, undefined)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，异步,私钥签名
*/
  async encryptPriKeyContent(content: string, priKey: string): Promise<string> {
    let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
    let keyPair = await this.getKeyPair(undefined, priKey)
    let signAlg = "RSA1024|PKCS1|SHA256";
    let signer = cryptoFramework.createSign(signAlg);
    await signer.init(keyPair.priKey)
    let signData = await signer.sign(plainTextBlob)
    this.setSignDataBlob(signData)
    let helper = new util.Base64Helper()
    return helper.encodeToString(signData.data)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，同步,私钥签名  RSA1024|PKCS1|NoHash|OnlySign
*/
  private signDataBlob?: cryptoFramework.DataBlob

  private setSignDataBlob(signData: cryptoFramework.DataBlob) {
    this.signDataBlob = signData
  }

  encryptPriKeyContentSync(content: string, priKey: string, algName: string = "RSA1024|PKCS1|SHA256"): string {
    let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
    let keyPair = this.getKeyPairSync(undefined, priKey)
    let signAlg = algName;
    let signer = cryptoFramework.createSign(signAlg);
    signer.initSync(keyPair.priKey)
    let signData = signer.signSync(plainTextBlob)
    this.setSignDataBlob(signData)
    return new util.Base64Helper().encodeToStringSync(signData.data)
  }

  /*
* Author:AbnerMing
* Describe:解密内容，异步,公钥验签
*/
  async decryptPubKeyContent(content: string, pubKey: string,
    algName: string = "RSA1024|PKCS1|SHA256"): Promise<boolean> {
    if (this.signDataBlob != undefined) {
      let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
      let keyPair = await this.getKeyPair(pubKey, undefined)
      let verifyAlg = algName;
      let verifier = cryptoFramework.createVerify(verifyAlg);
      await verifier.init(keyPair.pubKey)
      let res = await verifier.verify(plainTextBlob, this.signDataBlob)
      return res
    }
    return false
  }

  /*
* Author:AbnerMing
* Describe:解密内容，同步,公钥验签
*/
  decryptPubKeyContentSync(content: string, pubKey: string, algName: string = "RSA1024|PKCS1|SHA256"): boolean {
    if (this.signDataBlob != undefined) {
      let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
      let keyPair = this.getKeyPairSync(pubKey, undefined)
      let verifyAlg = algName;
      let verifier = cryptoFramework.createVerify(verifyAlg);
      verifier.initSync(keyPair.pubKey)
      let res = verifier.verifySync(plainTextBlob, this.signDataBlob);
      return res
    }
    return false
  }

  /*
* Author:AbnerMing
* Describe:加密内容，同步,公私钥加密
*/
  private encryptContentSync(content: string, pubKey?: string, priKey?: string): string {
    // 将公钥包装数据pubKeyBlob转换成密钥对类型KeyPair
    let keyPair = this.getKeyPairSync(pubKey, priKey)
    // 创建 Cipher对象
    let cipher = cryptoFramework.createCipher('RSA1024|PKCS1')
    // 初始化加密模式，指定密钥keyPair.pubKey
    cipher.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, pubKey != undefined ? keyPair.pubKey : keyPair.priKey,
      null);
    // 包装要加密的明文
    let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) };
    // 传入明文，获取加密后的数据
    let encryptBlob = cipher.doFinalSync(plainTextBlob)
    // 返回加密后的字符串
    return new util.Base64Helper().encodeToStringSync(encryptBlob.data)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，异步,公私钥加密
*/
  private async encryptContent(content: string, pubKey?: string, priKey?: string): Promise<string> {
    // 将公钥包装数据pubKeyBlob转换成密钥对类型KeyPair
    let keyPair = await this.getKeyPair(pubKey, priKey);
    // 创建 Cipher对象
    let cipher = cryptoFramework.createCipher('RSA1024|PKCS1');
    // 初始化加密模式，指定密钥keyPair.pubKey
    await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, pubKey != undefined ? keyPair.pubKey : keyPair.priKey,
      null);
    // 包装要加密的明文
    let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) };
    // 传入明文，获取加密后的数据
    let encryptBlob = await cipher.doFinal(plainTextBlob);
    // 返回加密后的字符串
    return new util.Base64Helper().encodeToStringSync(encryptBlob.data);
  }

  /*
* Author:AbnerMing
* Describe:获取公钥私钥对
*/
  private getKeyPair(publicKey?: string, privateKey?: string): Promise<cryptoFramework.KeyPair> {
    // 初始化Base64工具实例
    let base64Helper = new util.Base64Helper()
    // 公钥转换为Uint8Array，然后包装为DataBlob类型
    let pubKeyBlob: cryptoFramework.DataBlob | undefined =
      publicKey == undefined ? undefined : { data: base64Helper.decodeSync(publicKey) }
    let priKeyBlob: cryptoFramework.DataBlob | undefined =
      privateKey == undefined ? undefined : { data: base64Helper.decodeSync(privateKey) }
    // 创建RSA key生成器
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    // 将公钥包装数据pubKeyBlob转换成密钥对类型KeyPair
    let keyPair =
      rsaGenerator.convertKey(publicKey == undefined ? null : pubKeyBlob, privateKey == undefined ? null : priKeyBlob)
    return keyPair
  }

  /*
* Author:AbnerMing
* Describe:获取公钥私钥对 同步方式
*/
  private getKeyPairSync(publicKey?: string, privateKey?: string): cryptoFramework.KeyPair {
    // 初始化Base64工具实例
    let base64Helper = new util.Base64Helper()
    // 公钥转换为Uint8Array，然后包装为DataBlob类型
    let pubKeyBlob: cryptoFramework.DataBlob | undefined =
      publicKey == undefined ? undefined : { data: base64Helper.decodeSync(publicKey) }
    let priKeyBlob: cryptoFramework.DataBlob | undefined =
      privateKey == undefined ? undefined : { data: base64Helper.decodeSync(privateKey) }
    // 创建RSA key生成器
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    // 将公钥包装数据pubKeyBlob转换成密钥对类型KeyPair
    let keyPair = rsaGenerator.convertKeySync(publicKey == undefined ? null : pubKeyBlob,
      privateKey == undefined ? null : priKeyBlob)
    return keyPair
  }

  async getRandom(): Promise<Uint8Array> {
    let rand = cryptoFramework.createRandom();
    let seed = new Uint8Array([1, 2, 3]);
    rand.setSeed({ data: seed });
    let len = 12;
    let randOutput = await rand.generateRandom(len);
    return randOutput.data
  }

  getRandomSync(): Uint8Array {
    let rand = cryptoFramework.createRandom();
    let len = 12;
    return rand.generateRandomSync(len).data
  }

  /*
* Author:AbnerMing
* Describe:获取随机数 number
*/
  getRandomNumber(num: number = 100000): number {
    return Math.floor(Math.random() * num) + 1
  }
}