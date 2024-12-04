import cryptoFramework from "@ohos.security.cryptoFramework";
import buffer from "@ohos.buffer";

/**
 * AUTHOR:AbnerMing
 * DATE:2024/11/26
 * INTRODUCE:Sha加密
 * */
export class ShaUtil {
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
    if (!ShaUtil.shaUtil) {
      ShaUtil.shaUtil = new ShaUtil()
    }
    return ShaUtil.shaUtil
  }

  private static shaUtil: ShaUtil

  /*
* Author:AbnerMing
* Describe:加密消息 同步 - 字符串
*/
  encryptSync(content: string, algName: string = "SHA256"): string {
    let md = cryptoFramework.createMd(algName)
    // 数据量较少时，可以只做一次update，将数据全部传入，接口未对入参长度做限制
    md.updateSync({ data: new Uint8Array(buffer.from(content, 'utf-8').buffer) })
    let mdResult = md.digestSync()
    return this.uint8ArrayToHexString(mdResult.data)
  }

  /*
* Author:AbnerMing
* Describe:加密消息 同步 - 字符串
*/
  async encrypt(content: string, algName: string = "SHA256"): Promise<string> {
    let md = cryptoFramework.createMd(algName)
    // 数据量较少时，可以只做一次update，将数据全部传入，接口未对入参长度做限制
    md.updateSync({ data: new Uint8Array(buffer.from(content, 'utf-8').buffer) })
    let mdResult = await md.digest()
    return this.uint8ArrayToHexString(mdResult.data)
  }

  private uint8ArrayToHexString(uint8Array: Uint8Array): string {
    // 使用Array.from和toString转换每个字节为16进制并连接
    return Array.from(uint8Array).map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
}