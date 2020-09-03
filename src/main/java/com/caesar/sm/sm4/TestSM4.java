package com.caesar.sm.sm4;

import java.io.IOException;

/**
 * @author laijunlin
 * @date 2020-08-28 15:18
 */
public class TestSM4 {
    public static void main(String[] args) throws IOException {
        // 明文
        String plainText = "tecsun";

        SM4Utils sm4 = new SM4Utils();
        // 密钥
        //sm4.secretKey = "JeF8U9wHFOMfs2Y8";
        // 秘钥 16位秘钥
          sm4.secretKey = "JeF8U91234Mfs2Y8";
        sm4.hexString = false;

        System.out.println("ECB模式");
        String cipherText = sm4.encryptData_ECB(plainText);
        System.out.println("密文: " + cipherText);

        plainText = sm4.decryptData_ECB(cipherText);
        System.out.println("明文: " + plainText);

        System.out.println("CBC模式");
        // 初始化向量
        sm4.iv = "UISwD9fW6cFh9SNS";
        cipherText = sm4.encryptData_CBC(plainText);
        System.out.println("密文: " + cipherText);

        plainText = sm4.decryptData_CBC(cipherText);
        System.out.println("明文: " + plainText);
    }
}
