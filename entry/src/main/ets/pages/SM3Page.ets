import { ActionBar } from '@abner/bar'
import router from '@ohos.router'
import { md5Encrypt, md5EncryptSync, sM3Encrypt, sM3EncryptSync } from '@abner/security'

@Entry
@Component
struct SM3Page {
  build() {
    Column() {
      ActionBar({
        title: "SM3",
        leftText: "返回",
        onLeftClick: () => {
          router.back()
        },
      })

      Button("同步")
        .onClick(() => {
          let encryptContent = sM3EncryptSync("加密的数据")
          console.log("===加密后：" + encryptContent)
        }).margin({ top: 20 })
      Button("异步")
        .onClick(() => {
          sM3Encrypt("加密的数据").then((content) => {
            console.log("===加密后：" + content)
          })
        }).margin({ top: 20 })
    }
    .height('100%')
    .width('100%')
    .padding({ left: 10, right: 10 })
  }
}