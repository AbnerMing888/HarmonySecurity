## 介绍

HarmonySecurity是一个加密算法工具库，目前有MD5、Base64、SHA、SM3、AES、RSA算法，提供多种模式加解密。

目前功能项：

- 1、**支持MD5**
- 2、**支持Base64**
- 3、**支持SHA**
- 4、**支持SM3**
- 5、**支持AES**
- 6、**支持RSA**

## 开发环境

DevEco Studio NEXT Developer Beta1,Build Version: 5.0.3.900

Api版本：**12**

modelVersion：5.0.0

## 效果

<p align="center">
<img src="https://vipandroid-image.oss-cn-beijing.aliyuncs.com/harmony/security/security_01.png" width="200px" />
<img src="https://vipandroid-image.oss-cn-beijing.aliyuncs.com/harmony/security/security_02.png" width="200px" />
<img src="https://vipandroid-image.oss-cn-beijing.aliyuncs.com/harmony/security/security_03.png" width="200px" />
</p>

## 快速使用

方式一：在Terminal窗口中，执行如下命令安装三方包，DevEco Studio会自动在工程的oh-package.json5中自动添加三方包依赖。

**建议：在使用的模块路径下进行执行命令。**

```
ohpm install @abner/security
```

方式二：在工程的oh-package.json5中设置三方包依赖，配置示例如下：

```
"dependencies": { "@abner/security": "^1.0.0"}
```

## 代码使用

### 1、MD5

同步

```typescript
  let encryptContent = md5EncryptSync("加密的数据")
  console.log("===加密后：" + encryptContent)
```

异步

```typescript
 md5Encrypt("加密的数据").then((content) => {
   console.log("===加密后：" + content)
})
```

### 2、BASE64

编码同步

```typescript
  let encryptContent = base64EncodeSync("我是测试数据")
this.mBase64EncodeString = encryptContent
console.log("===编码后：" + encryptContent)
```

编码异步

```typescript
 base64Encode("我是测试数据").then((encryptContent) => {
  this.mBase64EncodeString = encryptContent
  console.log("===编码后：" + encryptContent)
})
```

解码同步

```typescript
 base64Decode(this.mBase64EncodeString).then((decode) => {
  console.log("===解码后：" + decode)
})
```

### 3、SHA

sha默认是SHA256，可以根据需要进行修改，在第二个参数传入即可。

同步

```typescript
 let encryptContent = shaEncryptSync("1")
 console.log("===加密后：" + encryptContent)
```
异步

```typescript
 shaEncrypt("1").then((content) => {
  console.log("===加密后：" + content)
})
```

修改algName

```typescript
 let encryptContent = shaEncryptSync("1","SHA256")
 console.log("===加密后：" + encryptContent)
```

### 4、SM3

同步

```typescript
 let encryptContent = sM3EncryptSync("加密的数据")
console.log("===加密后：" + encryptContent)
```

异步

```typescript
 sM3Encrypt("加密的数据").then((content) => {
  console.log("===加密后：" + content)
})
```

### 5、AES

随机生成SymKey密钥【异步】

```typescript
 aesGenerateSymKey().then((symKey) => {
  this.mSymKey = symKey
  console.log("===密钥：" + symKey)
})
```

随机生成SymKey密钥【同步】

```typescript
 let symKey = aesGenerateSymKeySync()
this.mSymKey = symKey
console.log("===密钥：" + symKey)
```

字符串生成密钥【异步】

```typescript
 aesGenerateSymKey("1234").then((symKey) => {
  this.mSymKey = symKey
  console.log("===密钥：" + symKey)
})
```

字符串生成密钥【同步】

```typescript
 let symKeyString = aesGenerateSymKeySync("1234")
this.mSymKey = symKeyString
console.log("===密钥：" + symKeyString)
```

加密数据【异步】【ECB模式】

```typescript
 aesEncryptString("123", this.mSymKey).then((result) => {
  this.encryptString = result
  console.log("===加密后数据：" + result)
})
```

解密数据【异步】【ECB模式】

```typescript
 aesDecryptString(this.encryptString, this.mSymKey).then((result) => {
  console.log("===解密后数据：" + result)
})
```

加密数据【同步】【ECB模式】

```typescript
 let result = aesEncryptStringSync("123", this.mSymKey)
this.encryptString = result
console.log("===加密后数据：" + result)
```

解密数据【同步】【ECB模式】

```typescript
  let decryptString = aesDecryptStringSync(this.encryptString!, this.mSymKey!)
console.log("===加密后数据：" + decryptString)
```

### 6、RSA

随机生成KeyPair密钥对 【异步】

```typescript
 rsaGenerateAsyKey().then((keyPair) => {
  let pubKey = keyPair.pubKey //公钥
  let priKey = keyPair.priKey //私钥
  this.priKey = priKey
  this.pubKey = pubKey
})
```
随机生成KeyPair密钥对【同步】

```typescript
 let keyPair = rsaGenerateAsyKeySync()
let pubKey1 = keyPair.pubKey //公钥
let priKey1 = keyPair.priKey //私钥
this.priKey = priKey1
this.pubKey = pubKey1
```

随机生成字符串密钥对 【异步】

```typescript
rsaGenerateAsyKeyPem().then((keyPairPem) => {
  let pubKey = keyPairPem.pubKey //公钥
  let priKey = keyPairPem.priKey //私钥
  console.log("===公钥：" + pubKey)
  console.log("===私钥：" + priKey)
})
```

随机生成字符串密钥对【同步】

```typescript
 let keyPairPem = generateAsyKeyPemSync()
let pubKeyPem = keyPairPem.pubKey //公钥
let priKeyPem = keyPairPem.priKey //私钥
console.log("===公钥：" + pubKeyPem)
console.log("===私钥：" + priKeyPem)
```
随机生成密钥对二进制【异步】

```typescript
 rsaGenerateAsyKeyDataBlob().then((dataBlobArray) => {
  let pubKey: cryptoFramework.DataBlob = dataBlobArray[0]
  let priKey: cryptoFramework.DataBlob = dataBlobArray[1]
  console.log("===公钥二进制：" + JSON.stringify(pubKey))
  console.log("===私钥二进制：" + JSON.stringify(priKey))
})
```

随机生成密钥对二进制【同步】

```typescript
 let dataBlobArray = rsaGenerateAsyKeyDataBlobSync()
let pubKey: cryptoFramework.DataBlob = dataBlobArray[0]
let priKey: cryptoFramework.DataBlob = dataBlobArray[1]
console.log("===公钥二进制：" + JSON.stringify(pubKey))
console.log("===私钥二进制：" + JSON.stringify(priKey))
```

指定二进制数据生成KeyPair密钥对【异步】

```typescript
rsaGenKeyPairByData(this.pkData, this.skData).then((keyPair) => {
  let pubKey = keyPair.pubKey //公钥
  let priKey = keyPair.priKey //私钥
  this.priKey = priKey
  this.pubKey = pubKey
})
```

指定二进制数据生成KeyPair密钥对【同步】

```typescript
 let keyPairByDataSync = rsaGenKeyPairByDataSync(this.pkData, this.skData)
let pubKeyPairByData = keyPairByDataSync.pubKey //公钥
let priKeyPairByData = keyPairByDataSync.priKey //私钥
this.priKey = priKeyPairByData
this.pubKey = pubKeyPairByData
```

二进制数据生成字符串密钥对【异步】

```typescript
 rsaGenKeyPairByDataPem(this.pkData, this.skData).then((keyPairPem) => {
  let pubKeyPem = keyPairPem.pubKey //公钥
  let priKeyPem = keyPairPem.priKey //私钥
  console.log("===公钥：" + pubKeyPem)
  console.log("===私钥：" + priKeyPem)
})
```

二进制数据生成字符串密钥对【同步】

```typescript
 let keyPairByDataPemSync = rsaGenKeyPairByDataPemSync(this.pkData, this.skData)
let pubKeyPairByDataPem = keyPairByDataPemSync.pubKey //公钥
let priKeyPairByDataPem = keyPairByDataPemSync.priKey //私钥
console.log("===公钥：" + pubKeyPairByDataPem)
console.log("===私钥：" + priKeyPairByDataPem)
```

字符串数据生成KeyPair密钥对【异步】

```typescript
 rsaGenKeyPairString(this.appRsaPublicKey, this.appRsaPrivateKey).then((keyPair) => {
  let pubKey = keyPair.pubKey
  let priKey = keyPair.priKey
  this.priKey = priKey
  this.pubKey = pubKey
})
```

字符串数据生成KeyPair密钥对【同步】

```typescript
 let keyPair2 = rsaGenKeyPairStringSync(this.publicPkcs1Str1024, this.priKeyPkcs1Str1024)
let pubKey3 = keyPair2.pubKey
let priKey3 = keyPair2.priKey
this.priKey = priKey3
this.pubKey = pubKey3
```

字符串数据生成字符串密钥对【异步】

```typescript
 rsaGenKeyPairStringPem(this.appRsaPublicKey, this.appRsaPrivateKey).then((keyPair) => {
          let pubKeyPem = keyPair.pubKey //公钥
          let priKeyPem = keyPair.priKey //私钥
          console.log("===公钥：" + pubKeyPem)
          console.log("===私钥：" + priKeyPem)
        })
```

字符串数据生成字符串密钥对【同步】

```typescript
 let keyPairStringPemSync = rsaGenKeyPairStringPemSync(this.publicPkcs1Str1024, this.priKeyPkcs1Str1024)
        let pubKeyPairStringPemSync = keyPairStringPemSync.pubKey //公钥
        let priKeyPairStringPemSync = keyPairStringPemSync.priKey //私钥
        console.log("===公钥：" + pubKeyPairStringPemSync)
        console.log("===私钥：" + priKeyPairStringPemSync)
```

字符串密钥方式加密【异步】

```typescript
 let message = "我是一段要加密的数据"
        console.log("===加密前数据：" + message)
        rsaEncryptString(message, this.publicKey).then((data) => {
          this.encryptString = data
          console.log("===加密后数据：" + data)
        }).catch((e: BusinessError) => {
          console.log("===加密错误：" + JSON.stringify(e.message))
        })
```

字符串密钥方式解密【异步】

```typescript
 //必须有私钥，还有要解密的数据
rsaDecryptString(this.encryptString, this.privateKey).then((data) => {
  console.log("===解密后数据：" + data)
})
```

字符串密钥方式加密【同步】

```typescript
 let message1 = "我是一段要加密的数据"
console.log("===加密前数据：" + message1)
this.encryptString = rsaEncryptStringSync(message1, this.publicKey)
console.log("===加密后数据：" + this.encryptString)
```

字符串密钥方式解密【同步】

```typescript
 //必须有私钥，还有要解密的数据
let data = rsaDecryptStringSync(this.encryptString, this.privateKey)
console.log("===解密后数据：" + data)
```

加密 KeyPair密钥方式【异步】 需要cryptoFramework.PubKey

```typescript
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
```

解密 KeyPair密钥方式【异步】

```typescript
 if (this.priKey != undefined && this.encryptDataBlob != undefined) {
          //必须有私钥，还有要解密的数据
          rsaDecryptDataBlob(this.encryptDataBlob, this.priKey).then((data) => {
            console.log("===解密后数据：" + data)
          })
        }
```

加密 KeyPair密钥方式【同步】

```typescript
 if (this.pubKey != undefined) {
          let message1 = "我是一段要加密的数据"
          console.log("===加密前数据：" + message1)
          this.encryptDataBlob = rsaEncryptDataBlobSync(message1, this.pubKey!)
          console.log("===加密后数据：" + JSON.stringify(this.encryptDataBlob))
        }
```

解密 KeyPair密钥方式【同步】

```typescript
 if (this.priKey != undefined && this.encryptDataBlob != undefined) {
          //必须有私钥，还有要解密的数据
          let data = rsaDecryptDataBlobSync(this.encryptDataBlob, this.priKey)
          console.log("===解密后数据：" + data)
        }
```

私钥签名 同步

```typescript
 let sign = rsaEncryptPriKeyContentSync("123", this.privateKey)
        console.log("=======签名：" + sign)
```

公钥验签 同步

```typescript
  let signResult = rsaDecryptPubKeyContentSync("123", this.publicKey)
        console.log("=======验签：" + signResult)
```

私钥签名 异步

```typescript
 rsaEncryptPriKeyContent("123", this.privateKey).then((sign) => {
          console.log("=======签名：" + sign)
        })
```

公钥验签 异步

```typescript
 rsaDecryptPubKeyContent("123", this.publicKey).then((signResult) => {
          console.log("=======验签：" + signResult)
        })
```

## 更多案例

可以查看相关Demo【右侧仓库地址】。

## 咨询作者

如果您在使用上有问题，解决不了，或者查看精华的鸿蒙技术文章，可扫码进行操作。

<p><img src="https://vipandroid-image.oss-cn-beijing.aliyuncs.com/harmony/abner.jpg" width="150"></p>

## License

```
Copyright (C) AbnerMing, HarmonySecurity Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
