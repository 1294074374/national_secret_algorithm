package com.caesar.sm.sm2;

import org.bouncycastle.util.encoders.Base64;

import java.util.HashMap;
import java.util.Map;

/**
 * @author laijunlin
 * @date 2020-09-02 17:22
 */
public class TestSM2 {
    public static void main(String[] args) throws Exception {
        Map<String, String> map = new HashMap<>();
        SM2Utils.createKey(map);
        String publicKey = map.get("publicKey");
        String privateKey = map.get("privateKey");
        System.out.println("---------------------------------------------------");
        System.out.println("公钥" + publicKey);
        System.out.println("私钥" + privateKey);
        //原文
        String plainText = "tecsun";
        System.out.println("---------------------------------------------------");
        System.out.println("加密");
        byte[] cipherText = SM2Utils.encrypt(publicKey, plainText.getBytes());
        System.out.println("密文:" + new String(Base64.encode(cipherText)));
        System.out.println("---------------------------------------------------");

        System.out.println("解密");
        byte[] plainTextByte = SM2Utils.decrypt(privateKey, cipherText);
        String cipherTextToPlainText = new String(plainTextByte);
        System.out.println("明文:" + cipherTextToPlainText);
        System.out.println("---------------------------------------------------");
        System.out.println("签名");
        String sign = SM2SignatureUtils.sign(privateKey, plainText);
        System.out.println("签名后的密文:" + sign);
        System.out.println("---------------------------------------------------");
        System.out.println("验签");
        boolean verify = SM2SignatureUtils.verify(publicKey, plainText, sign);
        System.out.println("验签结果:" + verify);
    }
}
