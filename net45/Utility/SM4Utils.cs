using System;
using System.Text;
using Org.BouncyCastle.Utilities.Encoders;

namespace net45.Utility
{
    /// <summary>
    /// SM4工具类
    /// </summary>
    public class SM4Utils
    {
        /// <summary>
        /// 密钥
        /// </summary>
        public string SecretKey = "";

        public string Iv = "";

        /// <summary>
        /// 是否为十六进制字符串
        /// </summary>
        public bool IsHexString = false;

        /// <summary>
        /// ECB模式加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <returns>密文</returns>
        public string EncryptECB(string plainText)
        {
            var ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            if (IsHexString)
            {
                keyBytes = Hex.Decode(SecretKey);
            }
            else
            {
                keyBytes = Encoding.UTF8.GetBytes(SecretKey);
            }

            var sm4 = new SM4();
            sm4.SM4SetKeyEncrypt(ctx, keyBytes);

            byte[] encrypted;
            if (IsHexString)
            {
                encrypted = sm4.SM4CryptECB(ctx, Hex.Decode(plainText));
            }
            else
            {
                encrypted = sm4.SM4CryptECB(ctx, Encoding.UTF8.GetBytes(plainText));
            }

            var cipherText = Convert.ToBase64String(encrypted);
            return cipherText;
        }

        /// <summary>
        /// ECB模式加密
        /// </summary>
        /// <param name="plainBytes">二进制明文</param>
        /// <param name="keyBytes">二进制密钥</param>
        /// <returns>二进制密文</returns>
        public byte[] EncryptECB(byte[] plainBytes, byte[] keyBytes)
        {
            var ctx = new SM4Context();
            ctx.IsPadding = false;
            ctx.Mode = SM4.SM4_ENCRYPT;

            var sm4 = new SM4();
            sm4.SM4SetKeyEncrypt(ctx, keyBytes);
            var encrypted = sm4.SM4CryptECB(ctx, plainBytes);
            return encrypted;

            //return Hex.Encode(encrypted);
        }

        /// <summary>
        /// ECB模式解密
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <returns>明文</returns>
        public string DecryptECB(string cipherText)
        {
            var ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            if (IsHexString)
            {
                keyBytes = Hex.Decode(SecretKey);
            }
            else
            {
                keyBytes = Encoding.UTF8.GetBytes(SecretKey);
            }

            var sm4 = new SM4();
            sm4.SM4SetKeyDecrypt(ctx, keyBytes);

            byte[] decrypted;
            if (IsHexString)
            {
                decrypted = sm4.SM4CryptECB(ctx, Hex.Decode(cipherText));
            }
            else
            {
                decrypted = sm4.SM4CryptECB(ctx, Convert.FromBase64String(cipherText));
            }

            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// CBC模式加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <returns>密文</returns>
        public string EncryptCBC(string plainText)
        {
            var ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (IsHexString)
            {
                keyBytes = Hex.Decode(SecretKey);
                ivBytes = Hex.Decode(Iv);
            }
            else
            {
                keyBytes = Encoding.UTF8.GetBytes(SecretKey);
                ivBytes = Encoding.UTF8.GetBytes(Iv);
            }

            var sm4 = new SM4();
            sm4.SM4SetKeyEncrypt(ctx, keyBytes);

            var encrypted = sm4.SM4CryptCBC(ctx, ivBytes, Encoding.UTF8.GetBytes(plainText));

            var cipherText = Encoding.UTF8.GetString(Hex.Encode(encrypted));
            return cipherText;
        }

        /// <summary>
        /// CBC模式解密
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <returns>明文</returns>
        public string DecryptCBC(string cipherText)
        {
            var ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (IsHexString)
            {
                keyBytes = Hex.Decode(SecretKey);
                ivBytes = Hex.Decode(Iv);
            }
            else
            {
                keyBytes = Encoding.UTF8.GetBytes(SecretKey);
                ivBytes = Encoding.UTF8.GetBytes(Iv);
            }

            var sm4 = new SM4();
            sm4.SM4SetKeyDecrypt(ctx, keyBytes);

            var decrypted = sm4.SM4CryptCBC(ctx, ivBytes, Hex.Decode(cipherText));
            return Encoding.UTF8.GetString(decrypted);
        }
    }
}