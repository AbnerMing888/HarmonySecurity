import { RsaUtil } from '../utils/RsaUtil';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { KeyPairPem } from '../model/KeyPairPem';
import { Md5Util } from '../utils/Md5Util';
import util from '@ohos.util';
import buffer from '@ohos.buffer';
import { ShaUtil } from '../utils/ShaUtil';
import { AesUtil } from '../utils/AesUtil';

/*
* Author:AbnerMing
* Describe:随机生成RSA密钥对 字符串 异步方式
*/
export function rsaGenerateAsyKeyPem(): Promise<KeyPairPem> {
  return RsaUtil.getInstance().generateAsyKeyPem()
}

/*
* Author:AbnerMing
* Describe:随机生成RSA密钥对 字符串 异步方式
*/
export function generateAsyKeyPemSync(): KeyPairPem {
  return RsaUtil.getInstance().generateAsyKeyPemSync()
}

/*
* Author:AbnerMing
* Describe:随机生成RSA密钥对 异步方式
*/
export function rsaGenerateAsyKey(): Promise<cryptoFramework.KeyPair> {
  return RsaUtil.getInstance().generateAsyKey()
}

/*
* Author:AbnerMing
* Describe:随机生成RSA密钥对 同步方式
*/
export function rsaGenerateAsyKeySync(): cryptoFramework.KeyPair {
  return RsaUtil.getInstance().generateAsyKeySync()
}


/*
* Author:AbnerMing
* Describe:生成RSA密钥对 异步
*/
export function rsaGenKeyPairByData(pubKeyData: Uint8Array, priKeyData: Uint8Array): Promise<cryptoFramework.KeyPair> {
  return RsaUtil.getInstance().genKeyPairByData(pubKeyData, priKeyData)
}

/*
* Author:AbnerMing
* Describe:生成RSA密钥对 字符串 异步
*/
export function rsaGenKeyPairByDataPem(pubKeyData: Uint8Array, priKeyData: Uint8Array): Promise<KeyPairPem> {
  return RsaUtil.getInstance().genKeyPairByDataPem(pubKeyData, priKeyData)
}

/*
* Author:AbnerMing
* Describe:生成RSA密钥对 字符串 同步
*/
export function rsaGenKeyPairByDataPemSync(pubKeyData: Uint8Array, priKeyData: Uint8Array): KeyPairPem {
  return RsaUtil.getInstance().genKeyPairByDataPemSync(pubKeyData, priKeyData)
}

/*
* Author:AbnerMing
* Describe:生成RSA密钥对 同步
*/
export function rsaGenKeyPairByDataSync(pubKeyData: Uint8Array, priKeyData: Uint8Array): cryptoFramework.KeyPair {
  return RsaUtil.getInstance().genKeyPairByDataSync(pubKeyData, priKeyData)
}


/*
* Author:AbnerMing
* Describe:随机生成RSA密钥对,返回二进制 异步方式
*/
export function rsaGenerateAsyKeyDataBlob(): Promise<cryptoFramework.DataBlob[]> {
  return RsaUtil.getInstance().generateAsyKeyDataBlob()
}

/*
* Author:AbnerMing
* Describe:随机生成RSA密钥对,返回二进制 同步方式
*/
export function rsaGenerateAsyKeyDataBlobSync(): cryptoFramework.DataBlob[] {
  return RsaUtil.getInstance().generateAsyKeyDataBlobSync()
}


/*
* Author:AbnerMing
* Describe:加密消息 同步方式  string
*/
export function rsaEncryptDataBlobSync(content: string, publicKey: cryptoFramework.PubKey): cryptoFramework.DataBlob {
  return RsaUtil.getInstance().encryptDataBlobSync(content, publicKey)
}

/*
* Author:AbnerMing
* Describe:加密消息 同步方式  返回string
*/
export function rsaEncryptStringSync(content: string, publicKey: string): string {
  return RsaUtil.getInstance().encryptStringSync(content, publicKey)
}

/*
* Author:AbnerMing
* Describe:加密消息 同步方式  返回string
*/
export function rsaOaepEncryptStringSync(content: string, publicKey: string): string {
  return RsaUtil.getInstance().oaepEncryptStringSync(content, publicKey)
}

/*
* Author:AbnerMing
* Describe:加密消息 异步方式  string
*/
export function rsaEncryptDataBlob(content: string,
  publicKey: cryptoFramework.PubKey): Promise<cryptoFramework.DataBlob> {
  return RsaUtil.getInstance().encryptDataBlob(content, publicKey)
}

/*
* Author:AbnerMing
* Describe:加密消息 异步方式  返回string
*/
export function rsaEncryptString(content: string, publicKey: string): Promise<string> {
  return RsaUtil.getInstance().encryptString(content, publicKey)
}

/*
* Author:AbnerMing
* Describe:加密消息 异步方式  返回string
*/
export function rsaOaepEncryptString(content: string, publicKey: string): Promise<string> {
  return RsaUtil.getInstance().oaepEncryptString(content, publicKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 异步  string
*/
export function rsaDecryptDataBlob(content: cryptoFramework.DataBlob,
  privateKey: cryptoFramework.PriKey): Promise<string> {
  return RsaUtil.getInstance().decryptDataBlob(content, privateKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 异步  返回string
*/
export function rsaDecryptString(content: string, privateKey: string): Promise<string> {
  return RsaUtil.getInstance().decryptString(content, privateKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 异步  返回string
*/
export function rsaOaepDecryptString(content: string, privateKey: string): Promise<string> {
  return RsaUtil.getInstance().oaepDecryptString(content, privateKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 同步  string
*/
export function rsaDecryptStringSync(content: string, privateKey: string): string {
  return RsaUtil.getInstance().decryptStringSync(content, privateKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 同步  string
*/
export function rsaOaepDecryptStringSync(content: string, privateKey: string): string {
  return RsaUtil.getInstance().oaepDecryptStringSync(content, privateKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 同步  string
*/
export function rsaDecryptDataBlobSync(content: cryptoFramework.DataBlob, privateKey: cryptoFramework.PriKey): string {
  return RsaUtil.getInstance().decryptDataBlobSync(content, privateKey)
}

/*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成RSA密钥对，同步方式
*/
export function rsaGenKeyPairStringSync(publicPkcs1Str1024: string,
  priKeyPkcs1Str1024: string): cryptoFramework.KeyPair {
  return RsaUtil.getInstance().genKeyPairStringSync(publicPkcs1Str1024, priKeyPkcs1Str1024)
}

/*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成RSA密钥对，异步方式
*/
export function rsaGenKeyPairString(publicPkcs1Str1024: string,
  priKeyPkcs1Str1024: string): Promise<cryptoFramework.KeyPair> {
  return RsaUtil.getInstance().genKeyPairString(publicPkcs1Str1024, priKeyPkcs1Str1024)
}

/*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成String密钥对，异步方式
*/
export function rsaGenKeyPairStringPem(publicPkcs1Str1024: string,
  priKeyPkcs1Str1024: string): Promise<KeyPairPem> {
  return RsaUtil.getInstance().genKeyPairStringPem(publicPkcs1Str1024, priKeyPkcs1Str1024)
}

/*
* Author:AbnerMing
* Describe:根据传递的公钥和私钥内容，生成RSA密钥对，同步方式
*/
export function rsaGenKeyPairStringPemSync(publicPkcs1Str1024: string,
  priKeyPkcs1Str1024: string): KeyPairPem {
  return RsaUtil.getInstance().genKeyPairStringPemSync(publicPkcs1Str1024, priKeyPkcs1Str1024)
}


/*
* Author:AbnerMing
* Describe:加密消息 异步方式  string OAEP模式
*/
export function rsaOaepEncryptDataBlob(content: string,
  publicKey: cryptoFramework.PubKey): Promise<cryptoFramework.DataBlob> {
  return RsaUtil.getInstance().oaepEncryptDataBlob(content, publicKey)
}


/*
* Author:AbnerMing
* Describe:加密消息 同步方式  string
*/
export function rsaOaepEncryptDataBlobSync(content: string,
  publicKey: cryptoFramework.PubKey): cryptoFramework.DataBlob {
  return RsaUtil.getInstance().oaepEncryptDataBlobSync(content, publicKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 异步  string
*/
export function rsaOaepDecryptDataBlob(content: cryptoFramework.DataBlob,
  privateKey: cryptoFramework.PriKey): Promise<string> {
  return RsaUtil.getInstance().oaepDecryptDataBlob(content, privateKey)
}

/*
* Author:AbnerMing
* Describe:解密消息 同步  string
*/
export function rsaOaepDecryptDataBlobSync(content: cryptoFramework.DataBlob,
  privateKey: cryptoFramework.PriKey): string {
  return RsaUtil.getInstance().oaepDecryptDataBlobSync(content, privateKey)
}


export function rsaGetRandom(): Promise<Uint8Array> {
  return RsaUtil.getInstance().getRandom()
}

export function rsaGetRandomSync(): Uint8Array {
  return RsaUtil.getInstance().getRandomSync()
}

/*
* Author:AbnerMing
* Describe:获取随机数 number
*/
export function rsaGetRandomNumber(num: number = 100000): number {
  return RsaUtil.getInstance().getRandomNumber(num)
}

/*
* Author:AbnerMing
* Describe:加密内容，异步,私钥签名
*/
export function rsaEncryptPriKeyContent(content: string, priKey: string,
  algName: string = "RSA1024|PKCS1|SHA256"): Promise<string> {
  return RsaUtil.getInstance().encryptPriKeyContent(content, priKey, algName)
}

/*
* Author:AbnerMing
* Describe:加密内容，同步,私钥签名
*/
export function rsaEncryptPriKeyContentSync(content: string, priKey: string,
  algName: string = "RSA1024|PKCS1|SHA256"): string {
  return RsaUtil.getInstance().encryptPriKeyContentSync(content, priKey, algName)
}

/*
* Author:AbnerMing
* Describe:解密内容，异步,公钥验签
*/
export function rsaDecryptPubKeyContent(content: string, pubKey: string,
  algName: string = "RSA1024|PKCS1|SHA256"): Promise<boolean> {
  return RsaUtil.getInstance().decryptPubKeyContent(content, pubKey, algName)
}

/*
* Author:AbnerMing
* Describe:解密内容，同步,公钥验签
*/
export function rsaDecryptPubKeyContentSync(content: string, pubKey: string,
  algName: string = "RSA1024|PKCS1|SHA256"): boolean {
  return RsaUtil.getInstance().decryptPubKeyContentSync(content, pubKey, algName)
}


/*
* Author:AbnerMing
* Describe: md5加密内容，同步
*/
export function md5EncryptSync(content: string): string {
  return Md5Util.getInstance().encryptSync(content)
}

/*
* Author:AbnerMing
* Describe: md5加密内容，异步
*/
export function md5Encrypt(content: string): Promise<string> {
  return Md5Util.getInstance().encrypt(content)
}

/*
* Author:AbnerMing
* Describe: base64 解密
*/
export async function base64Decode(content: string): Promise<string> {
  let blob = await new util.Base64Helper().decode(content)
  let decryptString = buffer.from(blob).toString('utf-8')
  return decryptString
}

/*
* Author:AbnerMing
* Describe: base64 解密
*/
export function base64DecodeSync(content: string): string {
  let blob = new util.Base64Helper().decodeSync(content)
  let decryptString = buffer.from(blob).toString('utf-8')
  return decryptString
}

/*
* Author:AbnerMing
* Describe: base64加密
*/
export function base64Encode(content: string): Promise<string> {
  let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
  return new util.Base64Helper().encodeToString(plainTextBlob.data)
}

/*
* Author:AbnerMing
* Describe: base64加密
*/
export function base64EncodeSync(content: string): string {
  let plainTextBlob: cryptoFramework.DataBlob = { data: new Uint8Array(buffer.from(content, 'utf-8').buffer) }
  return new util.Base64Helper().encodeToStringSync(plainTextBlob.data)
}

/*
* Author:AbnerMing
* Describe: sha加密内容，同步
*/
export function shaEncryptSync(content: string, algName: string = "SHA256"): string {
  return ShaUtil.getInstance().encryptSync(content, algName)
}

/*
* Author:AbnerMing
* Describe:sha加密内容，异步
*/
export function shaEncrypt(content: string, algName: string = "SHA256"): Promise<string> {
  return ShaUtil.getInstance().encrypt(content, algName)
}

/*
* Author:AbnerMing
* Describe: SM3加密内容，同步
*/
export function sM3EncryptSync(content: string): string {
  return ShaUtil.getInstance().encryptSync(content, "SM3")
}

/*
* Author:AbnerMing
* Describe:SM3加密内容，异步
*/
export function sM3Encrypt(content: string): Promise<string> {
  return ShaUtil.getInstance().encrypt(content, "SM3")
}

/*========================= AES START ===============================*/

/*
* Author:AbnerMing
* Describe:随机生成密钥-异步
*/
export function aesGenerateSymKey(text: string = "ABNERh82GtW/EVFF", algName: string = "AES128"): Promise<string> {
  return AesUtil.getInstance().generateSymKey(text, algName)
}

/*
* Author:AbnerMing
* Describe:随机生成密钥-同步
*/
export function aesGenerateSymKeySync(text: string = "ABNERh82GtW/EVFF", algName: string = "AES128"): string {
  return AesUtil.getInstance().generateSymKeySync(text, algName)
}

/*
* Author:AbnerMing
* Describe:加密消息 - 字符串 同步
*/
export function aesEncryptStringSync(content: string, key: string, cipherName: string = "AES128|ECB|PKCS7"): string {
  return AesUtil.getInstance().encryptStringSync(content, key, cipherName)
}

/*
* Author:AbnerMing
* Describe:加密消息 - 字符串 异步
*/
export function aesEncryptString(content: string, key: string,
  cipherName: string = "AES128|ECB|PKCS7"): Promise<string> {
  return AesUtil.getInstance().encryptString(content, key, cipherName)
}

/*
* Author:AbnerMing
* Describe:解密消息 - 字符串 异步
*/
export function aesDecryptString(text: string, key: string, cipherName: string = "AES128|ECB|PKCS7"): Promise<string> {
  return AesUtil.getInstance().decryptString(text, key, cipherName)
}

/*
* Author:AbnerMing
* Describe:解密消息 - 字符串 同步
*/
export function aesDecryptStringSync(text: string, key: string, cipherName: string = "AES128|ECB|PKCS7"): string {
  return AesUtil.getInstance().decryptStringSync(text, key, cipherName)
}


export function setSymKeyGeneratorName(symKeyGeneratorName: string): AesUtil {
  return AesUtil.getInstance().setSymKeyGeneratorName(symKeyGeneratorName)
}


/*========================= AES END ===============================*/