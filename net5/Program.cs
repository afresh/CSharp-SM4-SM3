using net45.Utility;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace net5
{
    class Program
    {
        static void Main(string[] args)
        {
            var strPlaintext = "{\"aaa\":\"01\",\"bbb\":\"02\"}"; //明文
            string strCipherText; //密文

            #region SM4调用

            var sm4 = new SM4Utils();
            sm4.SecretKey = "0123456789abcdef"; //密钥
            sm4.IsHexString = false; //是否为十六进制字符串
            strCipherText = sm4.EncryptECB(strPlaintext);
            Console.WriteLine(strCipherText); //PARawuGngHncyibcbScSffUyvkhjJC/UUOtYThNa8no=

            strPlaintext = sm4.DecryptECB(strCipherText);
            Console.WriteLine(strPlaintext); //{"aaa":"01","bbb":"02"}

            #endregion

            #region SM3调用

            var data = new byte[32];
            var bytes = Encoding.UTF8.GetBytes(strPlaintext);
            var sm3 = new SM3Digest();
            sm3.BlockUpdate(bytes, 0, bytes.Length);
            sm3.DoFinal(data, 0);
            strCipherText = new UTF8Encoding().GetString(Hex.Encode(data));
            Console.WriteLine(strCipherText); //6bfeb6d81f8df78aacfd49426cd249b8c5fdb48d2abf1654c9095ae7aa2b6ad2

            #endregion

            Console.ReadLine();
        }
    }
}
