import { GridView, ListView } from '@abner/refresh'
import { ListBean } from '../model/ListBean'
import { ActionBar } from '@abner/bar'
import router from '@ohos.router'
import cryptoFramework from '@ohos.security.cryptoFramework'
import {
  aesDecryptString,
  aesDecryptStringSync,
  aesEncryptString,
  aesEncryptStringSync,
  aesGenerateSymKey,
  aesGenerateSymKeySync,
  AesUtil
} from '@abner/security'

@Entry
@Component
struct AesPage {
  private mListBean: ListBean[] = [
    new ListBean(140, 1, "AES算法秘钥生成",
      ["随机生成密钥【异步】", "随机生成密钥【同步】", "字符串生成密钥【异步】", "字符串生成密钥【同步】"]),
    new ListBean(140, 2, "AES算法【ECB模式】",
      ["加密数据【异步】", "解密数据【异步】", "加密数据【同步】", "解密数据【同步】"])
  ]
  private mSymKey?: string //密钥
  encryptDataBlob?: cryptoFramework.DataBlob //加密之后的数据
  encryptString?: string //加密数据

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
      case 10: //随机生成SymKey密钥【异步】
        aesGenerateSymKey().then((symKey) => {
          this.mSymKey = symKey
          console.log("===密钥：" + symKey)
        })
        break
      case 11: //随机生成SymKey密钥【同步】
        let symKey = aesGenerateSymKeySync()
        this.mSymKey = symKey
        console.log("===密钥：" + symKey)
        break
      case 12: //字符串生成密钥【异步】
        aesGenerateSymKey("1234").then((symKey) => {
          this.mSymKey = symKey
          console.log("===密钥：" + symKey)
        })
        break
      case 13: //字符串生成密钥【同步】
        let symKeyString = aesGenerateSymKeySync("1234")
        this.mSymKey = symKeyString
        console.log("===密钥：" + symKeyString)
        break
      case 20: //加密数据【异步】【ECB模式】
        if (this.mSymKey != undefined) {
          aesEncryptString("123", this.mSymKey).then((result) => {
            this.encryptString = result
            console.log("===加密后数据：" + result)
          })
        }
        break

      case 21: //解密数据【异步】【ECB模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          aesDecryptString(this.encryptString, this.mSymKey).then((result) => {
            console.log("===解密后数据：" + result)
          })
        }

        break
      case 22: //加密数据【同步】【ECB模式】
        if (this.mSymKey != undefined) {
          let result = aesEncryptStringSync("123", this.mSymKey)
          this.encryptString = result
          console.log("===加密后数据：" + result)
        }
        break
      case 23: //解密数据【同步】【ECB模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          let decryptString = aesDecryptStringSync(this.encryptString!, this.mSymKey!)
          console.log("===加密后数据：" + decryptString)
        }

        break
      case 30: //加密数据【异步】 【GCM模式】
        if (this.mSymKey != undefined) {
          aesEncryptString("123", this.mSymKey!, AesUtil.gcmCipher).then((result) => {
            this.encryptString = result
            console.log("===加密后数据：" + result)
          })
        }

        break

      case 31: //解密数据【异步】 【GCM模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          aesDecryptString(this.encryptString!, this.mSymKey, AesUtil.gcmCipher).then((result) => {
            console.log("===解密后数据：" + result)
          })
        }

        break
      case 32: //加密数据【同步】【GCM模式】
        if (this.mSymKey != undefined) {
          let result = aesEncryptStringSync("123", this.mSymKey, AesUtil.gcmCipher)
          this.encryptString = result
          console.log("===加密后数据：" + result)
        }
        break
      case 33: //解密数据【同步】【GCM模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          let decryptString = aesDecryptStringSync(this.encryptString!, this.mSymKey, AesUtil.gcmCipher)
          console.log("===加密后数据：" + decryptString)
        }
        break
      case 40: //加密数据【异步】 【CBC模式】
        if (this.mSymKey != undefined) {
          aesEncryptString("123", this.mSymKey!, AesUtil.cbcCipher).then((result) => {
            this.encryptString = result
            console.log("===加密后数据：" + result)
          })
        }
        break

      case 41: //解密数据【异步】 【CBC模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          aesDecryptString(this.encryptString!, this.mSymKey, AesUtil.cbcCipher).then((result) => {
            console.log("===解密后数据：" + result)
          })
        }

        break
      case 42: //加密数据【同步】【CBC模式】
        if (this.mSymKey != undefined) {
          let result = aesEncryptStringSync("123", this.mSymKey, AesUtil.cbcCipher)
          this.encryptString = result
          console.log("===加密后数据：" + result)
        }
        break
      case 43: //解密数据【同步】【CBC模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          let decryptString = aesDecryptStringSync(this.encryptString!, this.mSymKey, AesUtil.cbcCipher)
          console.log("===加密后数据：" + decryptString)
        }
        break
      case 50: //加密数据【异步】 【CCM模式】
        if (this.mSymKey != undefined) {
          aesEncryptString("123", this.mSymKey!, AesUtil.ccmCipher).then((result) => {
            this.encryptString = result
            console.log("===加密后数据：" + result)
          })
        }
        break

      case 51: //解密数据【异步】 【CCM模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          aesDecryptString(this.encryptString!, this.mSymKey, AesUtil.ccmCipher).then((result) => {
            console.log("===解密后数据：" + result)
          })
        }

        break
      case 52: //加密数据【同步】【CCM模式】
        if (this.mSymKey != undefined) {
          let result = aesEncryptStringSync("123", this.mSymKey, AesUtil.ccmCipher)
          this.encryptString = result
          console.log("===加密后数据：" + result)
        }
        break
      case 53: //解密数据【同步】【CCM模式】
        if (this.mSymKey != undefined && this.encryptString != undefined) {
          let decryptString = aesDecryptStringSync(this.encryptString!, this.mSymKey, AesUtil.ccmCipher)
          console.log("===加密后数据：" + decryptString)
        }
        break
    }
  }

  build() {
    Column() {
      ActionBar({
        title: "AES算法",
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
}