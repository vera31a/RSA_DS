package a;

import org.apache.commons.codec.binary.Hex;

import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA_DS {
    public static void main(String[] args) {
        jdkRSA();
    }

    public static void jdkRSA(){

        String src="34114312";
        try {
            /*1.初始化密钥*/
            //获得gen对象实例
            KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair=keyPairGenerator.generateKeyPair();
            //获得公钥私钥。私钥签名，公钥验证
            RSAPublicKey rsaPublicKey=(RSAPublicKey)keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey=(RSAPrivateKey)keyPair.getPrivate();

            /*2.执行签名*/
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory=KeyFactory.getInstance("RSA");//得到实例
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);//通过keyFactory生成一个PrivateKey
            Signature signature=Signature.getInstance("MD5withRSA");//jdk的实现是MD5withRSA
            signature.initSign(privateKey);//签名的初始化方法，用私钥初始化
            signature.update(src.getBytes());
            byte[] result=signature.sign();
            System.out.println("jdk rsa sign"+ Hex.encodeHexString(result));

            /*3.验证签名*/
            X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory=KeyFactory.getInstance("RSA");
            PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
            signature=Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);//初始化验证方式
            signature.update(src.getBytes());
            signature.verify(result);
            System.out.println("jdkrsa_verified");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
