import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { GridView, ListView } from '@abner/refresh';
import { ListBean } from '../model/ListBean';
import {
  generateAsyKeyPemSync,
  rsaDecryptDataBlob,
  rsaDecryptDataBlobSync,
  rsaDecryptPubKeyContent,
  rsaDecryptPubKeyContentSync,
  rsaDecryptString,
  rsaDecryptStringSync,
  rsaEncryptDataBlob,
  rsaEncryptDataBlobSync,
  rsaEncryptPriKeyContent,
  rsaEncryptPriKeyContentSync,
  rsaEncryptString,
  rsaEncryptStringSync,
  rsaGenerateAsyKey,
  rsaGenerateAsyKeyDataBlob,
  rsaGenerateAsyKeyDataBlobSync,
  rsaGenerateAsyKeyPem,
  rsaGenerateAsyKeySync,
  rsaGenKeyPairByData,
  rsaGenKeyPairByDataPem,
  rsaGenKeyPairByDataPemSync,
  rsaGenKeyPairByDataSync,
  rsaGenKeyPairString,
  rsaGenKeyPairStringPem,
  rsaGenKeyPairStringPemSync,
  rsaGenKeyPairStringSync,
  rsaOaepDecryptDataBlob,
  rsaOaepDecryptDataBlobSync,
  rsaOaepDecryptString,
  rsaOaepEncryptDataBlob,
  rsaOaepEncryptDataBlobSync,
  rsaOaepEncryptString,
  rsaOaepEncryptStringSync
} from '@abner/security';
import { BusinessError } from '@kit.BasicServicesKit';
import { ActionBar } from '@abner/bar';
import router from '@ohos.router';

/**
 * AUTHOR:AbnerMing
 * DATE:2024/11/8
 * INTRODUCE:非对称加密  Rsa
 * */

@Entry
@Component
struct RsaPage {
  pkData: Uint8Array =
    new Uint8Array([48, 129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48, 129,
      137, 2, 129, 129, 0, 197, 64, 10, 198, 14, 110, 65, 92, 206, 35, 28, 123, 153, 24, 134, 255, 145, 74, 42,
      173, 40, 215, 146, 58, 143, 46, 10, 195, 154, 160, 69, 196, 220, 152, 179, 44, 111, 200, 84, 78, 215, 73,
      210, 181, 12, 29, 70, 68, 36, 135, 153, 89, 230, 202, 130, 212, 111, 243, 234, 92, 131, 62, 145, 50, 73, 48,
      104, 245, 46, 70, 45, 157, 147, 143, 140, 162, 156, 216, 220, 49, 121, 142, 194, 33, 223, 201, 0, 16, 163,
      210, 240, 118, 92, 147, 121, 220, 17, 114, 24, 52, 125, 135, 176, 88, 21, 83, 86, 17, 156, 88, 250, 48, 79,
      86, 128, 248, 105, 208, 133, 140, 13, 153, 164, 191, 136, 164, 44, 53, 2, 3, 1, 0, 1]);
  skData = new Uint8Array([48, 130, 2, 119, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 4, 130, 2,
    97, 48, 130, 2, 93, 2, 1, 0, 2, 129, 129, 0, 197, 64, 10, 198, 14, 110, 65, 92, 206, 35, 28, 123, 153, 24,
    134, 255, 145, 74, 42, 173, 40, 215, 146, 58, 143, 46, 10, 195, 154, 160, 69, 196, 220, 152, 179, 44, 111,
    200, 84, 78, 215, 73, 210, 181, 12, 29, 70, 68, 36, 135, 153, 89, 230, 202, 130, 212, 111, 243, 234, 92,
    131, 62, 145, 50, 73, 48, 104, 245, 46, 70, 45, 157, 147, 143, 140, 162, 156, 216, 220, 49, 121, 142, 194,
    33, 223, 201, 0, 16, 163, 210, 240, 118, 92, 147, 121, 220, 17, 114, 24, 52, 125, 135, 176, 88, 21, 83, 86,
    17, 156, 88, 250, 48, 79, 86, 128, 248, 105, 208, 133, 140, 13, 153, 164, 191, 136, 164, 44, 53, 2, 3, 1, 0,
    1, 2, 129, 128, 70, 75, 184, 139, 53, 1, 94, 17, 240, 244, 218, 101, 193, 253, 215, 190, 164, 204, 197, 192,
    200, 89, 107, 39, 171, 119, 65, 38, 204, 168, 105, 180, 234, 217, 16, 161, 185, 132, 175, 103, 25, 154, 153,
    153, 36, 36, 26, 178, 150, 66, 45, 8, 185, 19, 90, 228, 210, 177, 30, 200, 177, 141, 78, 184, 248, 59, 113,
    154, 145, 73, 160, 24, 73, 157, 86, 207, 186, 32, 95, 200, 106, 252, 107, 69, 170, 193, 216, 196, 181, 142,
    74, 203, 15, 18, 89, 228, 152, 19, 239, 21, 233, 98, 121, 214, 57, 187, 111, 239, 223, 248, 199, 70, 223,
    108, 108, 113, 234, 144, 155, 95, 246, 144, 244, 122, 39, 55, 127, 81, 2, 65, 0, 246, 96, 188, 0, 0, 104,
    221, 105, 139, 144, 63, 175, 209, 87, 179, 162, 88, 192, 99, 82, 125, 53, 54, 48, 70, 245, 239, 37, 15, 242,
    247, 84, 115, 187, 196, 95, 156, 40, 165, 60, 64, 102, 13, 229, 243, 2, 149, 0, 232, 226, 221, 192, 95, 11,
    12, 208, 5, 181, 98, 62, 210, 190, 141, 235, 2, 65, 0, 204, 244, 34, 10, 105, 80, 76, 116, 163, 35, 231,
    168, 187, 206, 189, 101, 215, 103, 80, 115, 86, 11, 34, 127, 203, 114, 84, 188, 121, 174, 169, 31, 142, 2,
    182, 27, 140, 225, 157, 227, 71, 98, 15, 203, 187, 213, 5, 190, 20, 121, 8, 30, 193, 100, 232, 101, 141, 8,
    124, 20, 29, 78, 6, 95, 2, 65, 0, 204, 43, 225, 224, 6, 118, 224, 117, 100, 200, 199, 94, 70, 23, 109, 175,
    173, 232, 208, 230, 61, 8, 105, 189, 156, 48, 150, 91, 154, 89, 248, 136, 173, 215, 254, 166, 84, 220, 130,
    1, 234, 68, 40, 100, 84, 251, 224, 202, 254, 51, 115, 28, 198, 38, 124, 25, 175, 129, 94, 199, 61, 17, 216,
    189, 2, 64, 72, 230, 129, 129, 48, 138, 134, 87, 106, 123, 231, 247, 165, 173, 216, 194, 115, 198, 228, 223,
    209, 120, 46, 114, 68, 92, 75, 117, 170, 214, 140, 131, 147, 208, 181, 19, 193, 157, 178, 186, 87, 246, 178,
    101, 166, 79, 20, 54, 211, 51, 101, 199, 2, 197, 48, 192, 134, 84, 193, 69, 170, 82, 201, 131, 2, 65, 0,
    213, 165, 55, 166, 131, 210, 195, 56, 250, 147, 195, 61, 205, 208, 189, 185, 40, 52, 50, 119, 137, 23, 246,
    46, 220, 108, 52, 23, 152, 154, 94, 32, 144, 195, 184, 249, 21, 168, 12, 57, 222, 18, 60, 117, 81, 157, 72,
    30, 155, 190, 165, 242, 228, 139, 240, 184, 145, 170, 103, 210, 160, 161, 135, 13]);
  priKey?: cryptoFramework.PriKey
  pubKey?: cryptoFramework.PubKey
  encryptDataBlob?: cryptoFramework.DataBlob //加密之后的数据
  encryptString?: string //加密之后的数据
  publicKey: string =
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDd10yJEClHxcJmbaWH5XqVt2G/" +
      "jOHCn2P4+7uDaWom54aqn5slUpw8DvNiRhbXx6Eeqa1cx/dB/SSOCvZx8lXz2SjL" +
      "cSm0rIONzk4sbAbpfybyld3C0v/3EoxuSE7yoRlErEBoC9G8LIGByxSMSWQv9kiT" +
      "9C0auaRknFwYIeCyxwIDAQAB"
  privateKey: string =
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAN3XTIkQKUfFwmZt" +
      "pYflepW3Yb+M4cKfY/j7u4NpaibnhqqfmyVSnDwO82JGFtfHoR6prVzH90H9JI4K" +
      "9nHyVfPZKMtxKbSsg43OTixsBul/JvKV3cLS//cSjG5ITvKhGUSsQGgL0bwsgYHL" +
      "FIxJZC/2SJP0LRq5pGScXBgh4LLHAgMBAAECgYAxSQPX7588MtNdrj54UqNJX9R3" +
      "mfUOKBst1b9zEphizE0+2va88/2B2lB4JNouVkuVZFz/n+1u266jYAwghJZTjKKo" +
      "w9WF3L+z4LhXBwVQ4Sx/PQk8c5dhdH/ptk99RVWCOQKGPpT6S+NMohXQmVP5FVu3" +
      "NkGTjcCDiOGoBDrxAQJBAPL0d/RYkXC6kxKHamagxWiFxHuyKDzBcyxGwN5pWvbd" +
      "Tb6zeAV5EiV8O/c/sFTDEl8h1dV823AR3dhqD5i5Hb0CQQDpwJv0IEyMJPWpjqOm" +
      "YKgxrq0XNUh/Y9eGCYGzKMO/SMW5JEzXKzc782ZdonS6COE5Y0lWhDBjqdpu5Vuz" +
      "3PDTAkA338E2kKfiJQZt3Ha7432C7ECjsfVPA65ZIGx6ugARhhO7J8sSdyWVOV0R" +
      "H7SNyc8P0dg7oNtWisVaYAn2NZyBAkBSYXBVHGD97zSpGj0wsNX2FIKqMDwpsU1O" +
      "zuDn/FDohEQy2Mk/99oShdio3U1YFzMRH53EIPhQ15bFCI5GGHLDAkEAzK1Htbi2" +
      "UiR1YEYheJwxPvLbq9bsYEWSZJo/6/biHhumcF65B9om6PejGOpkGZgOY7pggYGL" +
      "5sPQYMu4M46ssw=="
  private mListBean: ListBean[] = [
    new ListBean(280, 1, "RSA算法秘钥对生成",
      ["随机生成KeyPair密钥对【异步】", "随机生成KeyPair密钥对【同步】",
        "随机生成字符串密钥对【异步】", "随机生成字符串密钥对【同步】",
        "随机生成密钥对二进制【异步】", "随机生成密钥对二进制【同步】",
        "二进制生成KeyPair密钥对【异步】", "二进制生成KeyPair密钥对【同步】",
        "二进制生成字符串密钥对【异步】", "二进制生成字符串密钥对【同步】",
        "字符串生成KeyPair密钥对【异步】", "字符串生成KeyPair密钥对【同步】",
        "字符串生成字符串密钥对【异步】", "字符串生成字符串密钥对【同步】"
      ]),
    new ListBean(180, 2, "RSA算法【PKCS1模式】",
      ["KeyPair密钥方式加密【异步】", "KeyPair密钥方式解密【异步】", "KeyPair密钥方式加密【同步】",
        "KeyPair密钥方式解密【同步】",
        "字符串密钥方式加密【异步】", "字符串密钥方式解密【异步】", "字符串密钥方式加密【同步】", "字符串密钥方式解密【同步】"
      ]),
    new ListBean(180, 3, "RSA算法【PKCS1_OAEP模式】",
      ["KeyPair密钥方式加密【异步】", "KeyPair密钥方式解密【异步】", "KeyPair密钥方式加密【同步】",
        "KeyPair密钥方式解密【同步】", "字符串密钥方式加密【异步】", "字符串密钥方式解密【异步】", "字符串密钥方式加密【同步】",
        "字符串密钥方式解密【同步】"]),
    new ListBean(180, 4, "RSA算法【签名&验签】",
      ["私钥签名【同步】", "公钥验签【同步】", "私钥签名【异步】", "公钥验签【异步】"])

  ]

  @Builder
  listItemLayout(item: ListBean) {
    Column() {
      Text(item.name)
        .fontColor(Color.Red)
        .fontWeight(FontWeight.Bold)
        .margin({ top: 10, bottom: 10 })

      GridView({
        items: item.list,
        columnSize: 3,
        gridAttribute: (g) => {
          g.columnsGap = 5
          g.rowsGap = 10
        },
        itemLayout: (object: Object, index: number) => {
          this.gridItemLayout(object as string, Number(item.tag! + "" + index))
        }
      })
    }.height(item.height)
  }

  @Builder
  gridItemLayout(item: string, index: number) {
    Text(item)
      .width("100%")
      .height(40)
      .fontSize(12)
      .textAlign(TextAlign.Center)
      .padding(3)
      .fontColor(Color.Red)
      .border({ width: 1, radius: 5, color: Color.Red })
      .onClick(() => {
        this.itemClick(index)
      })
  }

  private itemClick(index: number) {
    switch (index) {
      case 10: //随机生成KeyPair密钥对 【异步】
        rsaGenerateAsyKey().then((keyPair) => {
          let pubKey = keyPair.pubKey //公钥
          let priKey = keyPair.priKey //私钥
          this.priKey = priKey
          this.pubKey = pubKey
        })
        break
      case 11: //随机生成KeyPair密钥对【同步】
        let keyPair = rsaGenerateAsyKeySync()
        let pubKey1 = keyPair.pubKey //公钥
        let priKey1 = keyPair.priKey //私钥
        this.priKey = priKey1
        this.pubKey = pubKey1
        break
      case 12: //随机生成字符串密钥对 【异步】
        rsaGenerateAsyKeyPem().then((keyPairPem) => {
          let pubKey = keyPairPem.pubKey //公钥
          let priKey = keyPairPem.priKey //私钥
          console.log("===公钥：" + pubKey)
          console.log("===私钥：" + priKey)
        })
        break
      case 13: //随机生成字符串密钥对【同步】
        let keyPairPem = generateAsyKeyPemSync()
        let pubKeyPem = keyPairPem.pubKey //公钥
        let priKeyPem = keyPairPem.priKey //私钥
        console.log("===公钥：" + pubKeyPem)
        console.log("===私钥：" + priKeyPem)
        break
      case 14: //随机生成密钥对二进制【异步】
        rsaGenerateAsyKeyDataBlob().then((dataBlobArray) => {
          let pubKey: cryptoFramework.DataBlob = dataBlobArray[0]
          let priKey: cryptoFramework.DataBlob = dataBlobArray[1]
          console.log("===公钥二进制：" + JSON.stringify(pubKey))
          console.log("===私钥二进制：" + JSON.stringify(priKey))
        })
        break
      case 15: //随机生成密钥对二进制【同步】
        let dataBlobArray = rsaGenerateAsyKeyDataBlobSync()
        let pubKey: cryptoFramework.DataBlob = dataBlobArray[0]
        let priKey: cryptoFramework.DataBlob = dataBlobArray[1]
        console.log("===公钥二进制：" + JSON.stringify(pubKey))
        console.log("===私钥二进制：" + JSON.stringify(priKey))
        break
      case 16: //指定二进制数据生成KeyPair密钥对【异步】
        rsaGenKeyPairByData(this.pkData, this.skData).then((keyPair) => {
          let pubKey = keyPair.pubKey //公钥
          let priKey = keyPair.priKey //私钥
          this.priKey = priKey
          this.pubKey = pubKey
        })

        break
      case 17: //指定二进制数据生成KeyPair密钥对【同步】
        let keyPairByDataSync = rsaGenKeyPairByDataSync(this.pkData, this.skData)
        let pubKeyPairByData = keyPairByDataSync.pubKey //公钥
        let priKeyPairByData = keyPairByDataSync.priKey //私钥
        this.priKey = priKeyPairByData
        this.pubKey = pubKeyPairByData
        break
      case 18: //二进制数据生成字符串密钥对【异步】
        rsaGenKeyPairByDataPem(this.pkData, this.skData).then((keyPairPem) => {
          let pubKeyPem = keyPairPem.pubKey //公钥
          let priKeyPem = keyPairPem.priKey //私钥
          console.log("===公钥：" + pubKeyPem)
          console.log("===私钥：" + priKeyPem)
        })
        break
      case 19: //二进制数据生成字符串密钥对【同步】
        let keyPairByDataPemSync = rsaGenKeyPairByDataPemSync(this.pkData, this.skData)
        let pubKeyPairByDataPem = keyPairByDataPemSync.pubKey //公钥
        let priKeyPairByDataPem = keyPairByDataPemSync.priKey //私钥
        console.log("===公钥：" + pubKeyPairByDataPem)
        console.log("===私钥：" + priKeyPairByDataPem)
        break
      case 110: //字符串数据生成KeyPair密钥对【异步】
        rsaGenKeyPairString(this.appRsaPublicKey, this.appRsaPrivateKey).then((keyPair) => {
          let pubKey = keyPair.pubKey
          let priKey = keyPair.priKey
          this.priKey = priKey
          this.pubKey = pubKey
        })
        break
      case 111: //字符串数据生成KeyPair密钥对【同步】
        let keyPair2 = rsaGenKeyPairStringSync(this.publicPkcs1Str1024, this.priKeyPkcs1Str1024)
        let pubKey3 = keyPair2.pubKey
        let priKey3 = keyPair2.priKey
        this.priKey = priKey3
        this.pubKey = pubKey3
        break
      case 112: //字符串数据生成字符串密钥对【异步】
        rsaGenKeyPairStringPem(this.appRsaPublicKey, this.appRsaPrivateKey).then((keyPair) => {
          let pubKeyPem = keyPair.pubKey //公钥
          let priKeyPem = keyPair.priKey //私钥
          console.log("===公钥：" + pubKeyPem)
          console.log("===私钥：" + priKeyPem)
        })
        break
      case 113: //字符串数据生成字符串密钥对【同步】
        let keyPairStringPemSync = rsaGenKeyPairStringPemSync(this.publicPkcs1Str1024, this.priKeyPkcs1Str1024)
        let pubKeyPairStringPemSync = keyPairStringPemSync.pubKey //公钥
        let priKeyPairStringPemSync = keyPairStringPemSync.priKey //私钥
        console.log("===公钥：" + pubKeyPairStringPemSync)
        console.log("===私钥：" + priKeyPairStringPemSync)
        break
      case 20: //加密 KeyPair密钥方式【异步】 需要cryptoFramework.PubKey
        if (this.pubKey != undefined) {
          let message = "我是一段要加密的数据"
          console.log("===加密前数据：" + message)
          rsaEncryptDataBlob(message, this.pubKey!).then((data) => {
            this.encryptDataBlob = data
            console.log("===加密后数据：" + JSON.stringify(data))
          }).catch((e: BusinessError) => {
            console.log("===加密错误：" + JSON.stringify(e.message))
          })
        }
        break

      case 21: //解密 KeyPair密钥方式【异步】
        if (this.priKey != undefined && this.encryptDataBlob != undefined) {
          //必须有私钥，还有要解密的数据
          rsaDecryptDataBlob(this.encryptDataBlob, this.priKey).then((data) => {
            console.log("===解密后数据：" + data)
          })
        }
        break
      case 22: //加密 KeyPair密钥方式【同步】
        if (this.pubKey != undefined) {
          let message1 = "我是一段要加密的数据"
          console.log("===加密前数据：" + message1)
          this.encryptDataBlob = rsaEncryptDataBlobSync(message1, this.pubKey!)
          console.log("===加密后数据：" + JSON.stringify(this.encryptDataBlob))
        }
        break
      case 23: //解密 KeyPair密钥方式【同步】
        if (this.priKey != undefined && this.encryptDataBlob != undefined) {
          //必须有私钥，还有要解密的数据
          let data = rsaDecryptDataBlobSync(this.encryptDataBlob, this.priKey)
          console.log("===解密后数据：" + data)
        }
        break
      case 24: //字符串密钥方式加密【异步】
        let message = "我是一段要加密的数据"
        console.log("===加密前数据：" + message)
        rsaEncryptString(message, this.publicKey).then((data) => {
          this.encryptString = data
          console.log("===加密后数据：" + data)
        }).catch((e: BusinessError) => {
          console.log("===加密错误：" + JSON.stringify(e.message))
        })
        break
      case 25: //字符串密钥方式解密【异步】
        if (this.encryptString != undefined) {
          //必须有私钥，还有要解密的数据
          rsaDecryptString(this.encryptString, this.privateKey).then((data) => {
            console.log("===解密后数据：" + data)
          })
        }
        break
      case 26: //字符串密钥方式加密【同步】
        let message1 = "我是一段要加密的数据"
        console.log("===加密前数据：" + message1)
        this.encryptString = rsaEncryptStringSync(message1, this.publicKey)
        console.log("===加密后数据：" + this.encryptString)
        break
      case 27: //字符串密钥方式解密【同步】
        if (this.encryptString != undefined) {
          //必须有私钥，还有要解密的数据
          let data = rsaDecryptStringSync(this.encryptString, this.privateKey)
          console.log("===解密后数据：" + data)
        }
        break
      case 30: //加密 KeyPair密钥方式【异步】PKCS1_OAEP模式
        if (this.pubKey != undefined) {
          let message2 = "我是一段要加密的数据"
          console.log("===加密前数据：" + message2)
          rsaOaepEncryptDataBlob(message2, this.pubKey!).then((data) => {
            this.encryptDataBlob = data
            console.log("===加密后数据：" + JSON.stringify(data))
          }).catch((e: BusinessError) => {
            console.log("===加密错误：" + JSON.stringify(e.message))
          })
        }

        break

      case 31: //解密 KeyPair密钥方式【异步】 PKCS1_OAEP模式
        if (this.priKey != undefined && this.encryptDataBlob != undefined) {
          //必须有私钥，还有要解密的数据
          rsaOaepDecryptDataBlob(this.encryptDataBlob, this.priKey).then((data) => {
            console.log("===解密后数据：" + data)
          })
        }

        break
      case 32: //加密 KeyPair密钥方式【同步】 PKCS1_OAEP模式
        if (this.pubKey != undefined) {
          let message3 = "我是一段要加密的数据"
          console.log("===加密前数据：" + message3)
          this.encryptDataBlob = rsaOaepEncryptDataBlobSync(message3, this.pubKey!)
          console.log("===加密后数据：" + JSON.stringify(this.encryptDataBlob))
        }
        break
      case 33: //解密 KeyPair密钥方式【同步】 PKCS1_OAEP模式
        if (this.priKey != undefined && this.encryptDataBlob != undefined) {
          //必须有私钥，还有要解密的数据
          let data = rsaOaepDecryptDataBlobSync(this.encryptDataBlob, this.priKey)
          console.log("===解密后数据：" + data)
        }
        break
      case 34: //字符串密钥方式加密【异步】
        let messageOaep = "我是一段要加密的数据"
        console.log("===加密前数据：" + messageOaep)
        rsaOaepEncryptString(messageOaep, this.publicKey).then((data) => {
          this.encryptString = data
          console.log("===加密后数据：" + data)
        }).catch((e: BusinessError) => {
          console.log("===加密错误：" + JSON.stringify(e.message))
        })
        break
      case 35: //字符串密钥方式解密【异步】
        if (this.encryptString != undefined) {
          //必须有私钥，还有要解密的数据
          rsaOaepDecryptString(this.encryptString, this.privateKey).then((data) => {
            console.log("===解密后数据：" + data)
          })
        }
        break
      case 36: //字符串密钥方式加密【同步】
        let messageOaep1 = "我是一段要加密的数据"
        console.log("===加密前数据：" + messageOaep1)
        this.encryptString = rsaOaepEncryptStringSync(messageOaep1, this.publicKey)
        console.log("===加密后数据：" + this.encryptString)
        break
      case 37: //字符串密钥方式解密【同步】
        let messageOaep2 = "我是一段要加密的数据"
        console.log("===加密前数据：" + messageOaep2)
        this.encryptString = rsaOaepEncryptStringSync(messageOaep2, this.publicKey)
        console.log("===加密后数据：" + this.encryptString)
        break
      case 40: //私钥签名 同步
        let sign = rsaEncryptPriKeyContentSync("123", this.privateKey)
        console.log("=======签名：" + sign)
        break
      case 41: //公钥验签 同步
        let signResult = rsaDecryptPubKeyContentSync("123", this.publicKey)
        console.log("=======验签：" + signResult)
        break
      case 42: //私钥签名 异步
        rsaEncryptPriKeyContent("123", this.privateKey).then((sign) => {
          console.log("=======签名：" + sign)
        })
        break
      case 43: //公钥验签 异步
        rsaDecryptPubKeyContent("123", this.publicKey).then((signResult) => {
          console.log("=======验签：" + signResult)
        })
        break
    }
  }

  build() {
    Column() {
      ActionBar({
        title: "RSA算法",
        leftText: "返回",
        onLeftClick: () => {
          router.back()
        },
      })
      ListView({
        items: this.mListBean,
        itemLayout: (item: Object, _: number) => {
          this.listItemLayout(item as ListBean)
        }
      })
    }
    .height('100%')
    .width('100%')
    .padding({ left: 10, right: 10 })
  }

  priKeyPkcs1Str1024: string =
    "-----BEGIN RSA PRIVATE KEY-----\n"
      + "MIICXQIBAAKBgQCwIN3mr21+N96ToxnVnaS+xyK9cNRAHiHGgrbjHw6RAj3V+l+W\n"
      + "Y68IhIe3DudVlzE9oMjeOQwkMkq//HCxNlIlFR6O6pa0mrXSwPRE7YKG97CeKk2g\n"
      + "YOS8YEh8toAvm7xKbiLkXuuMlxrjP2j/mb5iI/UASFSPZiQ/IyxDr0AQaQIDAQAB\n"
      + "AoGAEvBFzBNa+7J4PXnRQlYEK/tvsd0bBZX33ceacMubHl6WVZbphltLq+fMTBPP\n"
      + "LjXmtpC+aJ7Lvmyl+wTi/TsxE9vxW5JnbuRT48rnZ/Xwq0eozDeEeIBRrpsr7Rvr\n"
      + "7ctrgzr4m4yMHq9aDgpxj8IR7oHkfwnmWr0wM3FuiVlj650CQQDineeNZ1hUTkj4\n"
      + "D3O+iCi3mxEVEeJrpqrmSFolRMb+iozrIRKuJlgcOs+Gqi2fHfOTTL7LkpYe8SVg\n"
      + "e3JxUdVLAkEAxvcZXk+byMFoetrnlcMR13VHUpoVeoV9qkv6CAWLlbMdgf7uKmgp\n"
      + "a1Yp3QPDNQQqkPvrqtfR19JWZ4uy1qREmwJALTU3BjyBoH/liqb6fh4HkWk75Som\n"
      + "MzeSjFIOubSYxhq5tgZpBZjcpvUMhV7Zrw54kwASZ+YcUJvmyvKViAm9NQJBAKF7\n"
      + "DyXSKrem8Ws0m1ybM7HQx5As6l3EVhePDmDQT1eyRbKp+xaD74nkJpnwYdB3jyyY\n"
      + "qc7A1tj5J5NmeEFolR0CQQCn76Xp8HCjGgLHw9vg7YyIL28y/XyfFyaZAzzK+Yia\n"
      + "akNwQ6NeGtXSsuGCcyyfpacHp9xy8qXQNKSkw03/5vDO\n"
      + "-----END RSA PRIVATE KEY-----\n";
  publicPkcs1Str1024: string =
    "-----BEGIN RSA PUBLIC KEY-----\n"
      + "MIGJAoGBALAg3eavbX433pOjGdWdpL7HIr1w1EAeIcaCtuMfDpECPdX6X5ZjrwiE\n"
      + "h7cO51WXMT2gyN45DCQySr/8cLE2UiUVHo7qlrSatdLA9ETtgob3sJ4qTaBg5Lxg\n"
      + "SHy2gC+bvEpuIuRe64yXGuM/aP+ZvmIj9QBIVI9mJD8jLEOvQBBpAgMBAAE=\n"
      + "-----END RSA PUBLIC KEY-----\n";
  appRsaPublicKey: string =
    "-----BEGIN PUBLIC KEY-----\n" +
      "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDo30nDNp9QEFyfQ3cyp4KKQpAW\n" +
      "X9hRQ6OD0tu2t/D28WQHqh41vP/45AF/NlKBkkM85z9KhmkefE4WFSBfLOa1TLPD\n" +
      "QzDMSIMMpHD2/DrKKBAa6ByBu9xxFKvwStVgE1xSZecGjo3kyncDX0WR3c1obaII\n" +
      "aZsIWU6vtvv8cndg0QIDAQAB\n" +
      "-----END PUBLIC KEY-----";
  appRsaPrivateKey: string =
    "-----BEGIN PRIVATE KEY-----\n" +
      "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOjfScM2n1AQXJ9D\n" +
      "dzKngopCkBZf2FFDo4PS27a38PbxZAeqHjW8//jkAX82UoGSQzznP0qGaR58ThYV\n" +
      "IF8s5rVMs8NDMMxIgwykcPb8OsooEBroHIG73HEUq/BK1WATXFJl5waOjeTKdwNf\n" +
      "RZHdzWhtoghpmwhZTq+2+/xyd2DRAgMBAAECgYAD5L3XO3nQ7SEbUZWz3VyfoqrF\n" +
      "kP8tJqgce2FMjglDm7gcL7I3HEycVPWYcqhQ/cjNgyFKBfLKfXIRyPMkXDwUOkR7\n" +
      "1lKcCr6ZGg04GhfGIZQcVaScNAIo4+Kbucni+/ipy5IeigE0OQWXnlk/Y6fJ/ZFn\n" +
      "+1qLP3VpST8vJrQd8QJBAPdmA1TlASttwNQQIx5POGOu1uIeIIrh7Ntc1YNkz21U\n" +
      "x8P3kMExUJYqCTMH6CZQkwTHITE/DRgES7tv4R4232kCQQDw9/urI9DfI3d3wexi\n" +
      "Lwk+r+cJr66rm6DGThX0j/ugNnBaWQkEu8nT+LiJX6iwJSFBgzjQJ4IAIQoOem7g\n" +
      "xrEpAkBJxwpHTuPCZ8CRfR5783QFhiZe2E0sHaPc5xplTLLvD9FjB3kLpAE8Rtzn\n" +
      "cvwwMOcnDZtAbGUjPGS5SOwBbqvBAkEAu5pljk0ZHdBP/6Wz8pDqIqryNeFYHPTS\n" +
      "C/HZOAks/wPDHyP4WH4XWPdoPFOEUnbl2EpgXfaUSKNwX+tEDa3DWQJAU0Ud7d1x\n" +
      "ntaHanRFo+blPAuyTigwkfhpYekPKKh/k8llWs4h0cJsVJVH0UCpAlQLf2ZO2bve\n" +
      "ydg/tooQdBXnmQ==\n" +
      "-----END PRIVATE KEY-----";
}