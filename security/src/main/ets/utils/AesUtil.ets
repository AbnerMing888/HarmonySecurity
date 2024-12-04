import cryptoFramework from '@ohos.security.cryptoFramework';
import buffer from '@ohos.buffer';
import util from '@ohos.util';
import { Md5Util } from './Md5Util';

/**
 * AUTHOR:AbnerMing
 * DATE:2024/11/9
 * INTRODUCE:对称加密
 * */
export class AesUtil {
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
    if (!AesUtil.aesUtil) {
      AesUtil.aesUtil = new AesUtil()
    }
    return AesUtil.aesUtil
  }

  private static aesUtil: AesUtil
  static ecbCipher: string = "AES128|ECB|PKCS7"
  static gcmCipher: string = "AES128|GCM|PKCS7"
  static cbcCipher: string = "AES128|CBC|PKCS7"
  static ccmCipher: string = "AES128|CCM"

  /*
* Author:AbnerMing
* Describe:随机生成密钥-同步
*/
  generateSymKeySync(text: string = "ABNERh82GtW/EVFF", algName: string = "AES128"): string {
    if (text.length != 16 && algName == "AES128") {
      text = Md5Util.getInstance().encryptSync(text).substring(0, 16)
    }
    const base = new util.Base64Helper()
    let symKeyGenerator = cryptoFramework.createSymKeyGenerator(algName)
    let dataUint8Array = this.stringToUint8Array(text)
    let keyBlob: cryptoFramework.DataBlob = { data: dataUint8Array }
    let promiseSymKey = symKeyGenerator.convertKeySync(keyBlob)
    let key = base.encodeToStringSync(promiseSymKey.getEncoded().data) // 将密钥转换为base64存储
    return key
  }

  /*
* Author:AbnerMing
* Describe:随机生成密钥-异步
*/
  // 字符串转成字节流
  stringToUint8Array(str: string) {
    return new Uint8Array(buffer.from(str, 'utf-8').buffer);
  }

  async generateSymKey(text: string = "ABNERh82GtW/EVFF", algName: string = "AES128"): Promise<string> {
    if (text.length != 16 && algName == "AES128") {
      text = Md5Util.getInstance().encryptSync(text).substring(0, 16)
    }
    const base = new util.Base64Helper()
    let symKeyGenerator = cryptoFramework.createSymKeyGenerator(algName)
    let dataUint8Array = this.stringToUint8Array(text)
    let keyBlob: cryptoFramework.DataBlob = { data: dataUint8Array }
    let promiseSymKey = await symKeyGenerator.convertKey(keyBlob)
    let key = base.encodeToString(promiseSymKey.getEncoded().data) // 将密钥转换为base64存储
    return key
  }

  /*
* Author:AbnerMing
* Describe:生成随机数
*/
  generateRandom(len: number) {
    let rand = cryptoFramework.createRandom();
    let generateRandSync = rand.generateRandomSync(len);
    return generateRandSync;
  }


  private mSymKeyGeneratorName: string = "AES128"

  setSymKeyGeneratorName(symKeyGeneratorName: string): AesUtil {
    this.mSymKeyGeneratorName = symKeyGeneratorName
    return AesUtil.getInstance()
  }

  /*
* Author:AbnerMing
* Describe:加密消息 - 字符串 同步
*/
  encryptStringSync(content: string, key: string, cipherName: string = "AES128|ECB|PKCS7"): string {
    const base = new util.Base64Helper()
    let globalResult = ''
    try {
      let globalCipher = cryptoFramework.createCipher(cipherName)
      let symAlgName = this.mSymKeyGeneratorName
      let symKeyGenerator = cryptoFramework.createSymKeyGenerator(symAlgName)
      let dataUint8Array = base.decodeSync(key)
      let keyBlob: cryptoFramework.DataBlob = { data: dataUint8Array }
      let promiseSymKey = symKeyGenerator.convertKeySync(keyBlob)
      globalCipher.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, promiseSymKey, null)
      let result = globalCipher.doFinalSync({ data: this.stringToUint8Array(content) })
      return base.encodeToStringSync(result.data)
    } catch (err) {
      console.info(err.message)
    } finally {
      //还原
      this.mSymKeyGeneratorName = "AES128"
    }
    return globalResult
  }

  /*
* Author:AbnerMing
* Describe:加密消息 - 字符串 异步
*/
  async encryptString(content: string, key: string, cipherName: string = "AES128|ECB|PKCS7"): Promise<string> {
    const base = new util.Base64Helper()
    let globalResult = ''
    try {
      let globalCipher = cryptoFramework.createCipher(cipherName)
      let symAlgName = this.mSymKeyGeneratorName
      let symKeyGenerator = cryptoFramework.createSymKeyGenerator(symAlgName)
      let dataUint8Array = await base.decode(key)
      let keyBlob: cryptoFramework.DataBlob = { data: dataUint8Array }
      let promiseSymKey = await symKeyGenerator.convertKey(keyBlob)

      await globalCipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, promiseSymKey, null)
      let result = await globalCipher.doFinal({ data: this.stringToUint8Array(content) })
      return base.encodeToString(result.data)
    } catch (err) {
      console.info(err.message)
    } finally {
      //还原
      this.mSymKeyGeneratorName = "AES128"
    }
    return globalResult
  }

  /*
* Author:AbnerMing
* Describe:解密消息 - 字符串 异步
*/
  async decryptString(text: string, key: string, cipherName: string = "AES128|ECB|PKCS7"): Promise<string> {
    const base = new util.Base64Helper()
    let globalResult = ''
    try {
      let globalCipher = cryptoFramework.createCipher(cipherName)
      let symAlgName = this.mSymKeyGeneratorName
      let symKeyGenerator = cryptoFramework.createSymKeyGenerator(symAlgName)
      let dataUint8Array = await base.decode(key)
      let keyBlob: cryptoFramework.DataBlob = { data: dataUint8Array }
      let promiseSymKey = await symKeyGenerator.convertKey(keyBlob)
      await globalCipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, promiseSymKey, null)
      let plainText: cryptoFramework.DataBlob = { data: base.decodeSync(text) }
      let result = await globalCipher.doFinal(plainText)
      return this.uint8ArrayToString(result.data)
    } catch (err) {
      console.info(err.message)
    } finally {
      //还原
      this.mSymKeyGeneratorName = "AES128"
    }
    return globalResult
  }

  /*
* Author:AbnerMing
* Describe:解密消息 - 字符串 同步
*/
  decryptStringSync(text: string, key: string, cipherName: string = "AES128|ECB|PKCS7"): string {
    const base = new util.Base64Helper()
    let globalResult = ''
    try {
      let globalCipher = cryptoFramework.createCipher(cipherName)
      let symAlgName = this.mSymKeyGeneratorName
      let symKeyGenerator = cryptoFramework.createSymKeyGenerator(symAlgName)
      let dataUint8Array = base.decodeSync(key)
      let keyBlob: cryptoFramework.DataBlob = { data: dataUint8Array }
      let promiseSymKey = symKeyGenerator.convertKeySync(keyBlob)
      globalCipher.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, promiseSymKey, null)
      let plainText: cryptoFramework.DataBlob = { data: base.decodeSync(text) }
      let result = globalCipher.doFinalSync(plainText)
      return this.uint8ArrayToString(result.data)
    } catch (err) {
      console.info(err.message)
    } finally {
      //还原
      this.mSymKeyGeneratorName = "AES128"
    }
    return globalResult
  }

  /*
* Author:AbnerMing
* Describe:字节流转成可理解的字符串
*/
  private uint8ArrayToString(array: Uint8Array) {
    // 将UTF-8编码转换成Unicode编码
    let out: string = '';
    let index: number = 0;
    let len: number = array.length;
    while (index < len) {
      let character = array[index++];
      switch (character >> 4) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
          out += String.fromCharCode(character);
          break;
        case 12:
        case 13:
          out += String.fromCharCode(((character & 0x1F) << 6) | (array[index++] & 0x3F));
          break;
        case 14:
          out += String.fromCharCode(((character & 0x0F) << 12) | ((array[index++] & 0x3F) << 6) |
            ((array[index++] & 0x3F) << 0));
          break;
        default:
          break;
      }
    }
    return out;
  }

  private genGcmParamsSpec() {
    let ivBlob = this.generateRandom(12);
    let arr = [1, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes
    let dataAad = new Uint8Array(arr);
    let aadBlob: cryptoFramework.DataBlob = { data: dataAad };
    arr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 16 bytes
    let dataTag = new Uint8Array(arr);
    let tagBlob: cryptoFramework.DataBlob = {
      data: dataTag
    };
    // GCM的authTag在加密时从doFinal结果中获取，在解密时填入init函数的params参数中
    let gcmParamsSpec: cryptoFramework.GcmParamsSpec = {
      iv: ivBlob,
      aad: aadBlob,
      authTag: tagBlob,
      algName: "GcmParamsSpec"
    };
    return gcmParamsSpec;
  }
}