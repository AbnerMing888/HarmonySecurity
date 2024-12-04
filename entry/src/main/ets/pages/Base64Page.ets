import { ActionBar } from '@abner/bar'
import router from '@ohos.router'
import { base64Decode, base64DecodeSync, base64Encode, base64EncodeSync } from '@abner/security'

@Entry
@Component
struct Base64Page {
  private mBase64EncodeString: string = "" //编码后

  build() {
    Column() {
      ActionBar({
        title: "Base64",
        leftText: "返回",
        onLeftClick: () => {
          router.back()
        },
      })

      Button("编码同步")
        .onClick(() => {
          let encryptContent = base64EncodeSync("我是测试数据")
          this.mBase64EncodeString = encryptContent
          console.log("===编码后：" + encryptContent)
        }).margin({ top: 20 })
      Button("编码异步")
        .onClick(() => {
          base64Encode("我是测试数据").then((encryptContent) => {
            this.mBase64EncodeString = encryptContent
            console.log("===编码后：" + encryptContent)
          })
        }).margin({ top: 20 })
      Button("解码同步")
        .onClick(() => {
          if (this.mBase64EncodeString != undefined) {
            let decode = base64DecodeSync(this.mBase64EncodeString)
            console.log("===解码后：" + decode)
          }
        }).margin({ top: 20 })
      Button("解码异步")
        .onClick(() => {
          if (this.mBase64EncodeString != undefined) {
            base64Decode(this.mBase64EncodeString).then((decode) => {
              console.log("===解码后：" + decode)
            })
          }
        }).margin({ top: 20 })
    }
    .height('100%')
    .width('100%')
    .padding({ left: 10, right: 10 })
  }
}