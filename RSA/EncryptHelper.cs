using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RSA
{
    /// <summary>
    /// RSA加密（无长度限制）
    /// </summary>
    public class RSAHelper
    {
        //通过EncryptHelper.RSAKey方法生成私钥和公钥
        public static string PrivateKey = "xxx";
        public static string PublicKey = "yyy";

        /// <summary>
        /// 加密
        /// </summary>
        public static string Encrypt(string rawInput)
        {
            return RsaEncrypt(rawInput, PublicKey);
        }

        /// <summary>
        /// 解密
        /// </summary>
        public static string Decrypt(string encryptedInput)
        {
            return RsaDecrypt(encryptedInput, PrivateKey);
        }

        /// <summary>
        /// 生成密钥
        /// </summary>
        public static void RsaKey(out string xmlKeys, out string xmlPublicKey)
        {
            var rsa = new RSACryptoServiceProvider();
            xmlKeys = rsa.ToXmlString(true);
            xmlPublicKey = rsa.ToXmlString(false);
        }

        /// <summary>
        /// 加密
        /// </summary>
        private static string RsaEncrypt(string rawInput, string publicKey)
        {
            if (string.IsNullOrEmpty(rawInput))
            {
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(publicKey))
            {
                throw new ArgumentException("Invalid Public Key");
            }

            using var rsaProvider = new RSACryptoServiceProvider();
            var inputBytes = Encoding.UTF8.GetBytes(rawInput); //有含义的字符串转化为字节流
            rsaProvider.FromXmlString(publicKey); //载入公钥
            int bufferSize = (rsaProvider.KeySize / 8) - 11; //单块最大长度
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(inputBytes),
                outputStream = new MemoryStream())
            {
                while (true)
                {
                    //分段加密
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var encryptedBytes = rsaProvider.Encrypt(temp, false);
                    outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                }

                return Convert.ToBase64String(outputStream.ToArray()); //转化为字节流方便传输
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        private static string RsaDecrypt(string encryptedInput, string privateKey)
        {
            if (string.IsNullOrEmpty(encryptedInput))
            {
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(privateKey))
            {
                throw new ArgumentException("Invalid Private Key");
            }

            using var rsaProvider = new RSACryptoServiceProvider();
            var inputBytes = Convert.FromBase64String(encryptedInput);
            rsaProvider.FromXmlString(privateKey);
            var bufferSize = rsaProvider.KeySize / 8;
            var buffer = new byte[bufferSize];
            using MemoryStream inputStream = new MemoryStream(inputBytes),
                outputStream = new MemoryStream();
            while (true)
            {
                var readSize = inputStream.Read(buffer, 0, bufferSize);
                if (readSize <= 0)
                {
                    break;
                }

                var temp = new byte[readSize];
                Array.Copy(buffer, 0, temp, 0, readSize);
                var rawBytes = rsaProvider.Decrypt(temp, false);
                outputStream.Write(rawBytes, 0, rawBytes.Length);
            }

            return Encoding.UTF8.GetString(outputStream.ToArray());
        }
        
        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="str">需签名的数据</param>
        /// <returns>签名后的值</returns>
        public static string Sign(string str)
        {
            //根据需要加签时的哈希算法转化成对应的hash字符节
            byte[] bt = Encoding.GetEncoding("utf-8").GetBytes(str);
            var md5 = new MD5CryptoServiceProvider();
            byte[] rgbHash = md5.ComputeHash(bt);

            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.FromXmlString(PrivateKey);
            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("MD5");//此处是你需要加签的hash算法，需要和上边你计算的hash值的算法一致，不然会报错。
            byte[] inArray = formatter.CreateSignature(rgbHash);
            return Convert.ToBase64String(inArray);
        }

        /// <summary>
        /// 签名验证
        /// </summary>
        /// <param name="str">待验证的字符串</param>
        /// <param name="sign">加签之后的字符串</param>
        /// <returns>签名是否符合</returns>
        public static bool SignCheck(string str, string sign)
        {
            try
            {
                byte[] bt = Encoding.GetEncoding("utf-8").GetBytes(str);
                var md5 = new MD5CryptoServiceProvider();
                byte[] rgbHash = md5.ComputeHash(bt);

                RSACryptoServiceProvider key = new RSACryptoServiceProvider();
                key.FromXmlString(PublicKey);
                RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
                deformatter.SetHashAlgorithm("MD5");
                byte[] rgbSignature = Convert.FromBase64String(sign);
                if (deformatter.VerifySignature(rgbHash, rgbSignature))
                {
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}