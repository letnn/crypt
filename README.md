# Jwt crypt

基于Jwt的字符串加密与解密

# 开始使用

#### 安装组件
使用 composer 命令进行安装或下载源代码使用。

```composer require letnn/crypt```

#### 调用
```php
// 加密
$password = \letnn\Crypt::Encode("123456", "key");

// 解密
print \letnn\Crypt::Decode($password, "key");
```

#### 签名算法
```支持 HS256 HS384 HS512 RS256 RS384 RS512```
```默认 HS256```
