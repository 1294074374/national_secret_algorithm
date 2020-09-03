package com.caesar.sm.sm2;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * @author laijunlin
 * @date 2020-09-02 17:13
 */
public class SM2SignatureUtils {
    private static final String userId = "user";
    public static String summary(String msg) {
        //1.摘要
        byte[] md = new byte[32];
        SM3Digest sm = new SM3Digest();
        sm.update(msg.getBytes(), 0, msg.getBytes().length);
        sm.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        return s.toUpperCase();
    }


    /**
     * 签名
     * @return
     */
    public static String sign(String privateKey,String plainText) {
        String summaryString =  summary(plainText);
        String prikS = new String(Base64.encode(Util.hexToByte(privateKey)));
        byte[] sign = null; //摘要签名
        try {
            sign = SM2Utils.sign(userId.getBytes(), Base64.decode(prikS.getBytes()), Util.hexToByte(summaryString));
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Util.getHexString(sign);
    }


    /**
     * 验签
     * @return
     */
    public static boolean verify(String publicKey,String summary,String sign) {
        summary =summary(summary);
        String pubkS = new String(Base64.encode(Util.hexToByte(publicKey)));
        boolean vs = false; //验签结果
        try {
            vs = SM2Utils.verifySign(userId.getBytes(), Base64.decode(pubkS.getBytes()), Util.hexToByte(summary), Util.hexToByte(sign));
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return vs;
    }


}
