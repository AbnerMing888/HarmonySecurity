import { ActionBar } from '@abner/bar';
import { ListView } from '@abner/refresh';
import router from '@ohos.router';

@Entry
@Component
struct Index {
  private items: string[] = ["MD5", "Base64", "SHA", "SM3", "AES", "RSA"]
  private routerLink: string[] = ["pages/Md5Page",
    "pages/Base64Page",
    "pages/ShaPage",
    "pages/SM3Page",
    "pages/AesPage",
    "pages/RsaPage"]

  @Builder
  listItemLayout(item: string, index: number) {
    Column() {
      Button(item)
        .onClick(() => {
          router.pushUrl({ url: this.routerLink[index] })
        })
    }.justifyContent(FlexAlign.Start)
    .width("100%")
    .margin({ top: 10 })
  }

  build() {
    Column() {
      ActionBar({
        title: "加密算法"
      })
      ListView({
        items: this.items,
        itemLayout: (item: Object, index: number) => {
          this.listItemLayout(item as string, index)
        }
      }).margin({ top: 20 })
    }
  }
}