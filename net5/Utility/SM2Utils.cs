using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace net45.Utility
{
    public class SM2Utils
    {
        public static void GenerateKeyPair(out ECPoint pubk, out BigInteger prik)
        {
            var sm2 = SM2.Instance;
            var key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            var ecpriv = (ECPrivateKeyParameters)key.Private;
            var ecpub = (ECPublicKeyParameters)key.Public;
            var privateKey = ecpriv.D;
            var publicKey = ecpub.Q;

            //System.Console.Out.WriteLine("公钥: " + Encoding.ASCII.GetString(Hex.Encode(publicKey.GetEncoded())).ToUpper());
            //System.Console.Out.WriteLine("私钥: " + Encoding.ASCII.GetString(Hex.Encode(privateKey.ToByteArray())).ToUpper());
            pubk = publicKey;
            prik = privateKey;
        }

        public static string Encrypt(byte[] publicKey, byte[] data)
        {
            if (null == publicKey || publicKey.Length == 0)
            {
                return null;
            }
            if (data == null || data.Length == 0)
            {
                return null;
            }

            var source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            var cipher = new Cipher();
            var sm2 = SM2.Instance;

            var userKey = sm2.ecc_curve.DecodePoint(publicKey);

            var c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            var c3 = new byte[32];
            cipher.Dofinal(c3);

            var sc1 = Encoding.ASCII.GetString(Hex.Encode(c1.GetEncoded()));
            var sc2 = Encoding.ASCII.GetString(Hex.Encode(source));
            var sc3 = Encoding.ASCII.GetString(Hex.Encode(c3));

            return (sc1 + sc2 + sc3).ToUpper();
        }

        public static byte[] Decrypt(byte[] privateKey, byte[] encryptedData)
        {
            if (null == privateKey || privateKey.Length == 0)
            {
                return null;
            }
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }

            var data = Encoding.ASCII.GetString(Hex.Encode(encryptedData));

            var c1Bytes = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(0, 130)));
            var c2Len = encryptedData.Length - 97;
            var c2 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130, 2 * c2Len)));
            var c3 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130 + 2 * c2Len, 64)));

            var sm2 = SM2.Instance;
            var userD = new BigInteger(1, privateKey);

            //ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);

            var c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            var cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }

        //[STAThread]
        //public static void Main()
        //{
        //    GenerateKeyPair();

        //    String plainText = "ererfeiisgod";
        //    byte[] sourceData = Encoding.Default.GetBytes(plainText);

        //    //下面的秘钥可以使用generateKeyPair()生成的秘钥内容  
        //    // 国密规范正式私钥  
        //    String prik = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
        //    // 国密规范正式公钥  
        //    String pubk = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";

        //    System.Console.Out.WriteLine("加密: ");
        //    String cipherText = SM2Utils.Encrypt(Hex.Decode(pubk), sourceData);
        //    System.Console.Out.WriteLine(cipherText);
        //    System.Console.Out.WriteLine("解密: ");
        //    plainText = Encoding.Default.GetString(SM2Utils.Decrypt(Hex.Decode(prik), Hex.Decode(cipherText)));
        //    System.Console.Out.WriteLine(plainText);

        //    Console.ReadLine();
        //}
    }
}
