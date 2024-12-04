import cryptoFramework from '@ohos.security.cryptoFramework';
import buffer from '@ohos.buffer';

/**
 * AUTHOR:AbnerMing
 * DATE:2024/11/25
 * INTRODUCE:MD5加密
 * */
export class Md5Util {
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
    if (!Md5Util.md5Util) {
      Md5Util.md5Util = new Md5Util()
    }
    return Md5Util.md5Util
  }

  private static md5Util: Md5Util

  /*
* Author:AbnerMing
* Describe:加密消息 同步 - 字符串
*/
  encryptSync(content: string): string {
    let md = cryptoFramework.createMd('MD5');
    md.updateSync({ data: new Uint8Array(buffer.from(content, 'utf-8').buffer) });
    let mdOutput = md.digestSync();

    return this.uint8ArrayToHexString(mdOutput.data);
  }

  /*
* Author:AbnerMing
* Describe:加密消息 异步 - 字符串
*/
  async encrypt(content: string): Promise<string> {
    let md = cryptoFramework.createMd('MD5');
    await md.update({ data: new Uint8Array(buffer.from(content, 'utf-8').buffer) });
    let mdOutput = await md.digest();
    return this.uint8ArrayToHexString(mdOutput.data);
  }

  private uint8ArrayToHexString(uint8Array: Uint8Array): string {
    // 使用Array.from和toString转换每个字节为16进制并连接
    return Array.from(uint8Array).map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
}