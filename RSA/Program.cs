using System;

namespace RSA
{
    class Program
    {
        static void Main(string[] args)
        {
            RSAHelper.RsaKey(out RSAHelper.PrivateKey, out RSAHelper.PublicKey);
            string data = @"待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：RSACryptoServiceProvider.KeySize / 8 - 11），而加密后得到密文的字节数，正好是密钥的长度值除以 8（即：RSACryptoServiceProvider.KeySize / 8）。
　　                    所以，如果要加密较长的数据，则可以采用分段加解密的方式，实现方式如下：";
            string encryptStr = RSAHelper.Encrypt(data);
            Console.WriteLine("加密后结果：" + encryptStr);

            string signStr = RSAHelper.Sign(encryptStr);
            Console.WriteLine("加签后结果：" + signStr);

            bool result = RSAHelper.SignCheck(encryptStr, signStr);

            Console.WriteLine("签名验证结果：" + result);

            string decryptStr = RSAHelper.Decrypt(encryptStr);
            Console.WriteLine(decryptStr);
        }
    }
}