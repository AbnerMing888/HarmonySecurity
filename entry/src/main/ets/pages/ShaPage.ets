import { ActionBar } from '@abner/bar'
import router from '@ohos.router'
import { md5Encrypt, md5EncryptSync, shaEncrypt, shaEncryptSync } from '@abner/security'

@Entry
@Component
struct ShaPage {
  build() {
    Column() {
      ActionBar({
        title: "SHA",
        leftText: "返回",
        onLeftClick: () => {
          router.back()
        },
      })

      Button("同步")
        .onClick(() => {
          let encryptContent = shaEncryptSync("1")
          console.log("===加密后：" + encryptContent)
        }).margin({ top: 20 })
      Button("异步")
        .onClick(() => {
          shaEncrypt("1").then((content) => {
            console.log("===加密后：" + content)
          })
        }).margin({ top: 20 })
    }
    .height('100%')
    .width('100%')
    .padding({ left: 10, right: 10 })
  }
}