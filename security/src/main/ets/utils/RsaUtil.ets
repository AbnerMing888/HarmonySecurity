import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer, util } from '@kit.ArkTS';
import { KeyPairPem } from '../model/KeyPairPem';

/**
 * AUTHOR:AbnerMing
 * DATE:2024/11/8
 * INTRODUCE:非对称加密
 * */
export class RsaUtil {
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
    if (!RsaUtil.rsaUtil) {
      RsaUtil.rsaUtil = new RsaUtil()
    }
    return RsaUtil.rsaUtil
  }

  private static rsaUtil: RsaUtil

  /*
* Author:AbnerMing
* Describe:随机生成RSA密钥对,返回PEM字符串 异步方式
*/
  async generateAsyKeyPem(): Promise<KeyPairPem> {
    let keyPair = await this.generateAsyKey()
    return this.getKeyPairPem(keyPair)
  }


  /*
* Author:AbnerMing
* Describe:随机生成RSA密钥对,返回PEM字符串 异步方式
*/
  generateAsyKeyPemSync(): KeyPairPem {
    let keyPair = this.generateAsyKeySync()
    return this.getKeyPairPem(keyPair)
  }

  /*
 * Author:AbnerMing
 * Describe:随机生成RSA密钥对,返回二进制 异步方式
 */
  async generateAsyKey(): Promise<cryptoFramework.KeyPair> {
    // 创建一个AsyKeyGenerator实例
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024|PRIMES_2')
    // 使用密钥生成器随机生成非对称密钥对
    return rsaGenerator.generateKeyPair()
  }

  /*
 * Author:AbnerMing
 * Describe:随机生成RSA密钥对,返回二进制 同步方式
 */
  generateAsyKeySync(): cryptoFramework.KeyPair {
    // 创建一个AsyKeyGenerator实例
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024|PRIMES_2');
    return rsaGenerator.generateKeyPairSync()
  }


  /*
* Author:AbnerMing
* Describe:随机生成Uint8Array
*/
  randomUint8Array(length: number): Uint8Array {
    const uint8Array = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      uint8Array[i] = Math.floor(Math.random() * 256) // 生成0-255之间的随机数
    }
    return uint8Array
  }

  /*
* Author:AbnerMing
* Describe:生成RSA密钥对 异步
*/
  async genKeyPairByDataPem(pubKeyData: Uint8Array, priKeyData: Uint8Array): Promise<KeyPairPem> {
    let pubKeyBlob: cryptoFramework.DataBlob = { data: pubKeyData }
    let priKeyBlob: cryptoFramework.DataBlob = { data: priKeyData }
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    let keyPair = await rsaGenerator.convertKey(pubKeyBlob, priKeyBlob)
    return this.getKeyPairPem(keyPair)
  }

  /*
* Author:AbnerMing
* Describe:生成RSA密钥对 异步
*/
  async genKeyPairByData(pubKeyData: Uint8Array, priKeyData: Uint8Array): Promise<cryptoFramework.KeyPair> {
    let pubKeyBlob: cryptoFramework.DataBlob = { data: pubKeyData }
    let priKeyBlob: cryptoFramework.DataBlob = { data: priKeyData }
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    let keyPair = await rsaGenerator.convertKey(pubKeyBlob, priKeyBlob)
    return keyPair
  }

  /*
* Author:AbnerMing
* Describe:生成RSA密钥对 同步
*/
  genKeyPairByDataSync(pubKeyData: Uint8Array, priKeyData: Uint8Array): cryptoFramework.KeyPair {
    let pubKeyBlob: cryptoFramework.DataBlob = { data: pubKeyData }
    let priKeyBlob: cryptoFramework.DataBlob = { data: priKeyData }
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    let keyPair = rsaGenerator.convertKeySync(pubKeyBlob, priKeyBlob)
    return keyPair
  }

  /*
* Author:AbnerMing
* Describe:生成RSA密钥对 字符串 同步
*/
  genKeyPairByDataPemSync(pubKeyData: Uint8Array, priKeyData: Uint8Array): KeyPairPem {
    let pubKeyBlob: cryptoFramework.DataBlob = { data: pubKeyData }
    let priKeyBlob: cryptoFramework.DataBlob = { data: priKeyData }
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    let keyPair = rsaGenerator.convertKeySync(pubKeyBlob, priKeyBlob)
    return this.getKeyPairPem(keyPair)
  }

  /*
* Author:AbnerMing
* Describe:加密消息
*/
  async encryptContent(publicKey: cryptoFramework.PubKey,
    plainText: cryptoFramework.DataBlob): Promise<cryptoFramework.DataBlob> {
    let cipher = cryptoFramework.createCipher('RSA1024|PKCS1')
    await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, publicKey, null)
    let encryptData = await cipher.doFinal(plainText)
    return encryptData
  }

  /*
* Author:AbnerMing
* Describe:解密消息 异步
*/
  async decryptContent(privateKey: cryptoFramework.PriKey,
    cipherText: cryptoFramework.DataBlob): Promise<cryptoFramework.DataBlob> {
    let decoder = cryptoFramework.createCipher('RSA1024|PKCS1')
    await decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, privateKey, null)
    let decryptData = await decoder.doFinal(cipherText)
    return decryptData
  }


  /*
* Author:AbnerMing
* Describe:加密消息 同步方式
*/
  encryptContentSync(publicKey: cryptoFramework.PubKey, plainText: cryptoFramework.DataBlob): cryptoFramework.DataBlob {
    let cipher = cryptoFramework.createCipher('RSA1024|PKCS1')
    cipher.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, publicKey, null)
    let encryptData = cipher.doFinalSync(plainText)
    return encryptData
  }

  /*
* Author:AbnerMing
* Describe:加密消息 同步方式  string
*/
  encryptDataBlobSync(content: string, publicKey: cryptoFramework.PubKey): cryptoFramework.DataBlob {
    let plainText: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) };
    let dataBlob = this.encryptContentSync(publicKey, plainText)
    return dataBlob
  }

  /*
* Author:AbnerMing
* Describe:加密消息 异步方式  string
*/
  async encryptDataBlob(content: string, publicKey: cryptoFramework.PubKey): Promise<cryptoFramework.DataBlob> {
    let plainText: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) };
    let dataBlob = await this.encryptContent(publicKey, plainText)
    return dataBlob
  }

  /*
* Author:AbnerMing
* Describe:解密消息 同步方式
*/
  decryptContentSync(privateKey: cryptoFramework.PriKey,
    cipherText: cryptoFramework.DataBlob): cryptoFramework.DataBlob {
    let decoder = cryptoFramework.createCipher('RSA1024|PKCS1')
    decoder.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, privateKey, null)
    let decryptData = decoder.doFinalSync(cipherText)
    return decryptData
  }


  /*
* Author:AbnerMing
* Describe:解密消息 异步  string
*/
  async decryptDataBlob(content: cryptoFramework.DataBlob, privateKey: cryptoFramework.PriKey): Promise<string> {
    let decryptText = await this.decryptContent(privateKey, content)
    let decryptString = buffer.from(decryptText.data).toString('utf-8')
    return decryptString
  }

  /*
* Author:AbnerMing
* Describe:解密消息 同步  string
*/
  decryptDataBlobSync(content: cryptoFramework.DataBlob, privateKey: cryptoFramework.PriKey): string {
    let decryptText = this.decryptContentSync(privateKey, content)
    let decryptString = buffer.from(decryptText.data).toString('utf-8')
    return decryptString
  }


  /*
* Author:AbnerMing
* Describe:随机生成RSA密钥对,返回二进制 异步方式
*/
  async generateAsyKeyDataBlob(): Promise<cryptoFramework.DataBlob[]> {
    // 创建一个AsyKeyGenerator实例
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024|PRIMES_2')
    // 使用密钥生成器随机生成非对称密钥对
    let keyPair = await rsaGenerator.generateKeyPair()
    let pubKey = keyPair.pubKey
    let priKey = keyPair.priKey
    // 获取非对称密钥对的二进制数据
    let pkBlob = pubKey.getEncoded()
    let skBlob = priKey.getEncoded()
    let dataBlob: cryptoFramework.DataBlob[] = []
    dataBlob.push(pkBlob)
    dataBlob.push(skBlob)
    return dataBlob
  }

  /*
 * Author:AbnerMing
 * Describe:随机生成RSA密钥对,返回二进制 同步方式
 */
  generateAsyKeyDataBlobSync(): cryptoFramework.DataBlob[] {
    // 创建一个AsyKeyGenerator实例
    let rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024|PRIMES_2');
    // 使用密钥生成器随机生成非对称密钥对
    let dataBlob: cryptoFramework.DataBlob[] = []
    try {
      let keyPair = rsaGenerator.generateKeyPairSync()
      if (keyPair != null) {
        let pubKey = keyPair.pubKey
        let priKey = keyPair.priKey
        // 获取非对称密钥对的二进制数据
        let pkBlob = pubKey.getEncoded()
        let skBlob = priKey.getEncoded()
        dataBlob.push(pkBlob)
        dataBlob.push(skBlob)
      }
    } catch (e) {
    }
    return dataBlob
  }


  /*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成RSA密钥对，同步方式
*/
  genKeyPairStringPemSync(publicPkcs1Str1024: string, priKeyPkcs1Str1024: string): KeyPairPem {
    let asyKeyGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024');
    let keyPair = asyKeyGenerator.convertPemKeySync(publicPkcs1Str1024, priKeyPkcs1Str1024)
    return this.getKeyPairPem(keyPair)
  }

  /*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成RSA密钥对，异步方式
*/
  async genKeyPairStringPem(publicPkcs1Str1024: string, priKeyPkcs1Str1024: string): Promise<KeyPairPem> {
    let asyKeyGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    let keyPair = await asyKeyGenerator.convertPemKey(publicPkcs1Str1024, priKeyPkcs1Str1024)
    return this.getKeyPairPem(keyPair)
  }

  /*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成RSA密钥对，同步方式
*/
  genKeyPairStringSync(publicPkcs1Str1024: string, priKeyPkcs1Str1024: string): cryptoFramework.KeyPair {
    let asyKeyGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024');
    let keyPairData = asyKeyGenerator.convertPemKeySync(publicPkcs1Str1024, priKeyPkcs1Str1024)
    return keyPairData
  }

  /*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成RSA密钥对，异步方式
*/
  genKeyPairString(publicPkcs1Str1024: string, priKeyPkcs1Str1024: string): Promise<cryptoFramework.KeyPair> {
    let asyKeyGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024')
    return asyKeyGenerator.convertPemKey(publicPkcs1Str1024, priKeyPkcs1Str1024)
  }

  /*
* Author:AbnerMing
* Describe:加密消息 异步方式  string OAEP模式
*/
  async oaepEncryptDataBlob(content: string, publicKey: cryptoFramework.PubKey): Promise<cryptoFramework.DataBlob> {
    let plainText: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) };
    // RSA加解密PKCS1-OAEP模式填充字节流P
    let pSource = new Uint8Array([1, 2, 3, 4])
    let cipher = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1")
    // 进行加密操作初始化
    await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, publicKey, null)
    // get和set操作可以放在Cipher对象init之后，此处对cipher进行set和get操作
    cipher.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource)
    let cipherDataBlob = await cipher.doFinal(plainText)
    return cipherDataBlob
  }

  /*
* Author:AbnerMing
* Describe:加密消息 同步方式  string
*/
  oaepEncryptDataBlobSync(content: string, publicKey: cryptoFramework.PubKey): cryptoFramework.DataBlob {
    let plainText: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) };
    // RSA加解密PKCS1-OAEP模式填充字节流P
    let pSource = new Uint8Array([1, 2, 3, 4])
    let cipher = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1")
    // 进行加密操作初始化
    cipher.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, publicKey, null)
    // get和set操作可以放在Cipher对象init之后，此处对cipher进行set和get操作
    cipher.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource)
    let cipherDataBlob = cipher.doFinalSync(plainText)
    return cipherDataBlob
  }

  /*
* Author:AbnerMing
* Describe:解密消息 异步  string
*/
  async oaepDecryptDataBlob(content: cryptoFramework.DataBlob, privateKey: cryptoFramework.PriKey): Promise<string> {
    let pSource = new Uint8Array([1, 2, 3, 4])
    let decoder = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1");
    // get和set操作可以放在Cipher对象init之前，且与init之后等价，此处对decoder进行set和get操作
    decoder.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource);
    // 初始化解密操作
    await decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, privateKey, null);
    let decodeData = await decoder.doFinal(content);
    let decryptString = buffer.from(decodeData.data).toString('utf-8')
    return decryptString
  }

  /*
* Author:AbnerMing
* Describe:解密消息 同步  string
*/
  oaepDecryptDataBlobSync(content: cryptoFramework.DataBlob, privateKey: cryptoFramework.PriKey): string {
    // RSA加解密PKCS1-OAEP模式填充字节流P
    let pSource = new Uint8Array([1, 2, 3, 4]);
    let decoder = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1")
    // get和set操作可以放在Cipher对象init之前，且与init之后等价，此处对decoder进行set和get操作
    decoder.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource)
    // 初始化解密操作
    decoder.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, privateKey, null)
    let decodeData = decoder.doFinalSync(content)
    let decryptString = buffer.from(decodeData.data).toString('utf-8')
    return decryptString
  }

  private getKeyPairPem(keyPair: cryptoFramework.KeyPair): KeyPairPem {
    let priString = keyPair.priKey.getEncodedPem('PKCS8')
    let pubString = keyPair.pubKey.getEncodedPem('X509')
    return new KeyPairPem(priString, pubString)
  }


  /*
* Author:AbnerMing
* Describe:解密内容，异步,私钥解密
*/
  async decryptString(content: string, privateKey: string): Promise<string> {
    return this.decryptMessage(content, privateKey, false)
  }

  /*
* Author:AbnerMing
* Describe:解密内容，异步,私钥解密 oaep
*/
  async oaepDecryptString(content: string, privateKey: string): Promise<string> {
    return this.decryptMessage(content, privateKey, true)
  }

  /*
* Author:AbnerMing
* Describe:解密内容，同步,私钥解密 oaep
*/
  oaepDecryptStringSync(content: string, privateKey: string): string {
    return this.decryptMessageSync(content, privateKey, true)
  }

  /*
* Author:AbnerMing
* Describe:解密内容，同步,私钥解密
*/
  decryptStringSync(content: string, privateKey: string): string {
    return this.decryptMessageSync(content, privateKey, false)
  }

  /*
* Author:AbnerMing
* Describe:解密内容，异步,公私钥解密
*/
  private async decryptMessage(content: string, privateKey?: string, isOaep?: boolean): Promise<string> {
    let keyPair = await this.getKeyPair(undefined, privateKey);

    let decoder: cryptoFramework.Cipher

    if (isOaep) {
      let pSource = new Uint8Array([1, 2, 3, 4])
      decoder = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1");
      // get和set操作可以放在Cipher对象init之前，且与init之后等价，此处对decoder进行set和get操作
      decoder.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource);
      // 初始化解密操作
      await decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, keyPair.priKey, null);
    } else {
      // 创建 Cipher对象
      decoder = cryptoFramework.createCipher('RSA1024|PKCS1')
      await decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, keyPair.priKey, null)
    }

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
  private decryptMessageSync(content: string, privateKey?: string, isOaep?: boolean): string {
    let keyPair = this.getKeyPairSync(undefined, privateKey)

    let decoder: cryptoFramework.Cipher

    if (isOaep) {
      // RSA加解密PKCS1-OAEP模式填充字节流P
      let pSource = new Uint8Array([1, 2, 3, 4]);
      decoder = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1")
      // get和set操作可以放在Cipher对象init之前，且与init之后等价，此处对decoder进行set和get操作
      decoder.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource)
      // 初始化解密操作
      decoder.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, keyPair.priKey, null)
    } else {
      // 创建 Cipher对象
      decoder = cryptoFramework.createCipher('RSA1024|PKCS1')
      decoder.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, keyPair.priKey, null)
    }

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
  async encryptString(content: string, publicKey: string): Promise<string> {
    return this.encryptMessage(content, publicKey, false)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，异步,公钥加密  oaep
*/
  async oaepEncryptString(content: string, publicKey: string): Promise<string> {
    return this.encryptMessage(content, publicKey, true)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，同步,公钥加密
*/
  oaepEncryptStringSync(content: string, publicKey: string): string {
    return this.encryptMessageSync(content, publicKey, true)
  }


  /*
* Author:AbnerMing
* Describe:加密内容，同步,公钥加密
*/
  encryptStringSync(content: string, publicKey: string): string {
    return this.encryptMessageSync(content, publicKey, false)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，同步,公私钥加密
*/
  private encryptMessageSync(content: string, pubKey?: string, isOaep?: boolean): string {
    // 将公钥包装数据pubKeyBlob转换成密钥对类型KeyPair
    let keyPair = this.getKeyPairSync(pubKey, undefined)
    let cipher: cryptoFramework.Cipher

    if (isOaep) {
      // RSA加解密PKCS1-OAEP模式填充字节流P
      let pSource = new Uint8Array([1, 2, 3, 4])
      cipher = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1")
      // 进行加密操作初始化
      cipher.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, keyPair.pubKey, null)
      // get和set操作可以放在Cipher对象init之后，此处对cipher进行set和get操作
      cipher.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource)
    } else {
      // 创建 Cipher对象
      cipher = cryptoFramework.createCipher('RSA1024|PKCS1')
      // 初始化加密模式，指定密钥keyPair.pubKey
      try {
        cipher.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, pubKey != undefined ? keyPair.pubKey : keyPair.priKey,
          null);
      } catch (e) {
      }
    }
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
  private async encryptMessage(content: string, pubKey?: string, isOaep?: boolean): Promise<string> {
    // 将公钥包装数据pubKeyBlob转换成密钥对类型KeyPair
    let keyPair = await this.getKeyPair(pubKey, undefined)

    let cipher: cryptoFramework.Cipher

    if (isOaep) {
      // RSA加解密PKCS1-OAEP模式填充字节流P
      let pSource = new Uint8Array([1, 2, 3, 4])
      cipher = cryptoFramework.createCipher("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA1")
      // 进行加密操作初始化
      await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, keyPair.pubKey, null)
      // get和set操作可以放在Cipher对象init之后，此处对cipher进行set和get操作
      cipher.setCipherSpec(cryptoFramework.CipherSpecItem.OAEP_MGF1_PSRC_UINT8ARR, pSource)
    } else {
      // 创建 Cipher对象
      cipher = cryptoFramework.createCipher('RSA1024|PKCS1');
      // 初始化加密模式，指定密钥keyPair.pubKey
      await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, keyPair.pubKey, null);
    }

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

  private signDataBlob?: cryptoFramework.DataBlob

  private setSignDataBlob(signData: cryptoFramework.DataBlob) {
    this.signDataBlob = signData
  }

  /*
* Author:AbnerMing
* Describe:加密内容，异步,私钥签名
*/
  async encryptPriKeyContent(content: string, priKey: string,
    algName: string = "RSA1024|PKCS1|SHA256"): Promise<string> {
    let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
    let keyPair = await this.getKeyPair(undefined, priKey)
    let signAlg = algName
    let signer = cryptoFramework.createSign(signAlg);
    await signer.init(keyPair.priKey)
    let signData = await signer.sign(plainTextBlob)
    this.setSignDataBlob(signData)
    let helper = new util.Base64Helper()
    return helper.encodeToString(signData.data)
  }

  /*
* Author:AbnerMing
* Describe:加密内容，同步,私钥签名
*/
  encryptPriKeyContentSync(content: string, priKey: string, algName: string = "RSA1024|PKCS1|SHA256"): string {
    let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
    let keyPair = this.getKeyPairSync(undefined, priKey)
    let signAlg = algName
    let signer = cryptoFramework.createSign(signAlg)
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
}