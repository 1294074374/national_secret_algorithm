package com.caesar.sm.sm3;

import org.bouncycastle.util.encoders.Hex;

/**
 * @author laijunlin
 * @date 2020-08-28 15:10
 */
public class TestSM3 {
    public static void main(String[] args) {
        // 需要加密的原文
        byte[] msg1 = "ererfeiisgod".getBytes();
        byte[] md = new byte[32];
        SM3Digest sm3 = new SM3Digest();
        // 明文输入
        sm3.update(msg1, 0, msg1.length);

        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        System.out.println(s.toUpperCase());
    }
}
