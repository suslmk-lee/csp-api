package org.example;

import java.io.*;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import java.net.HttpURLConnection;
import java.net.URL;

import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class CspClass {

    public static void main(String[] args) {

        URI uri = null;
        long timestamp = new Date().getTime();
        String accessKey = args[0];
        String secretKey = args[1];
        String targetURL = "https://ncloud.apigw.gov-ntruss.com/vserver/v2/getRootPassword";
        String serverInstanceNo = "2008183";
        uri = URI.create(targetURL);
        String requestURI = uri.getPath();
        String privateKeyString = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAk2bosnrqbJcwlXc84UXHSmwci+5H/dqDGADaI0WYEGJdupeDP4Wgmx5XMmCWUYc+hEvU8gho5Bx1MrEiOzx131HeoHX1dAJXqg4LAuktHTrV/1RXLW6PQwZa6pA+Jroew/gR+tMkb56U4IkVjnh5fdos/OUpjCreBkBlr3ugrdlc2ZIxu8Q1fyPonSxaXbENWdXBpg0wx95UuD4haRqgaosFsBS+RmtIEVTDY07QnNF04NOVK2zq6k1/Ek9Y30OsBI56CbubUjK4VPiD+wPkkTz6MkubMSDcifuTtHTRpPkbDRjI/PP6jTfd092a2TC9eivZSptSPoBGIOypxr4hqQIDAQABAoIBAEBdrbtSZU+p7bM28ETGvbHH5+dK0/EMHDa9GIRSfYaaDafPRabVaT6TTyxWdQ2A61HF82UFOxhxPNQ3+WS4kBhGndqf5+ESrMk7fJ92xxZ+fLgUUkUqhDCWc9j9x8YNfCXDC8blsIF1VDmAYwNlpFfKj96XCz+D8JP2RvEMISwIljRObUIBq7jaLXh4uf3G8FGvAx/vEYrzw8Vl/LwJ1wJi3XGFVYtmZ4l09Rvw46GJB98yAJtnZI5WJYILacSBrJn+YCjggZAiWuShk/gU93XaElYQUqO/Qa8svWIWy/smEdlXKHkpSEIIeyQV+qAMwSUoud4txkoAQ9pENb91gUkCgYEA1xa9wVjfGOHVmKEPJuA9hzCAjXqAUDjEsPawQDzvFVvXcPdUomk+rdGIFQYo1VUj+TwgWEUWH0EYlzJrisxq7fgk9PYXjPSH1WaHWx5j0nT5aaI09yWDGpu/rHnMI9zZef3EK4iyTcExEdJ4NNX1MWj38FfkQPuKQp+l7OBqXy8CgYEAr3BPyEe14eRehMZeRBaWqSsTAB4BVVURh1XDmsWYxniLeKEuZXXWUxSpCZlecumHuIGHI4SZ9UcIibILmIuB6IGkYRrc35yEzjkPfPg9iDfo0hiEoJwV73V8JO1ebmUdfb+nU3j/8wG6baTj87CeRqbKCmnsyhgEnSoluqqUFqcCgYBOs3eDQ61+QUQSsPwGUY6x5MFlAynoMJ1n0xvypVkmC5DtONKzCqdwmnacmsBeLuUW0TVUlxLdJMiGqmBHTTzjDiUXrOQ5I1CAeR+V66zC2SJZ0Ixo0kUCe3LK/VYA2VKKHJynAUGcyc/WoZhyXMd26N2wB7jxPhj8/8WKwyKo6QKBgQCU6FUvf35nj3iSZfTZAfs69y6XaOBk12GbZzYxhgoYW3S2HMjOoWga+GxJk33RN1pVRsu3X/N1dqdOiGrDPZY0DOXC7hQPUECA8Xmt7t37YskgmmLoF9Oefi+zAC6osPaJJ0UU2p0UW6ErM0uwKXcOLL9Me3/aQOyZoY6IlARB/QKBgHSl8OkMGjFw6LUVIDqbld62o299gNrBvSTEtYCnyaHTjslOR74KEMGA6hNVrfbG3BHcnpXW+6M6xJqv9SiktnFeAyMAZMZJ03O2+1kNOR1mtCx4d8syXftjCYSg7Rcy5cDc2JRXdAHFwdiBwpDX12ZveVZOhakzbsyVdVz9FPbc-----END RSA PRIVATE KEY-----";

        String encodeParameter = getParameter(serverInstanceNo, privateKeyString);

        String signature = makeSignature(timestamp, accessKey, secretKey, requestURI, encodeParameter);

        String password = getData(timestamp, accessKey, targetURL + "?" + encodeParameter, signature);

        System.out.println(password);

    }

    public static String getParameter(String serverInstanceNo, String PrivateKeyString) {

        String encodeKey = URLEncoder.encode(PrivateKeyString, StandardCharsets.UTF_8);

        return "serverInstanceNo" + "=" + serverInstanceNo + "&" +
                "privateKey" + "=" + encodeKey + "&" +
                "responseFormatType" + "=" + "json";
    }

    public static String getData(long timestamp, String accessKey, String Url, String signature) {

        String ret = "";

        try {

            URL url = new URL(Url);
            HttpURLConnection conn = (HttpURLConnection)url.openConnection();

            conn.setRequestMethod("POST"); // http 메서드
            conn.setRequestProperty("Content-Type", "application/json"); // header Content-Type 정보
            conn.setRequestProperty("x-ncp-apigw-timestamp", String.valueOf(timestamp));
            conn.setRequestProperty("x-ncp-iam-access-key", accessKey);
            conn.setRequestProperty("x-ncp-apigw-signature-v2", signature);
            conn.setDoInput(true);
            conn.setDoOutput(true);

            // 서버로부터 데이터 읽어오기
            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line = null;

            while((line = br.readLine()) != null) {
                sb.append(line);
            }

            JSONObject obj = new JSONObject(sb.toString());
            JSONObject subObj = obj.getJSONObject("getRootPasswordResponse");
            System.out.println("Password = " + subObj.getString("rootPassword") + " / message = " + subObj.getString("returnMessage"));
            ret = subObj.getString("rootPassword");

        } catch (Exception e) {
            System.out.println(e);
        }
        return ret;
    }

    private static String makeSignature(long timestamp, String accessKey, String secretKey, String targetURL, String param) {

        URI uri = URI.create(targetURL);
        StringBuilder message = new StringBuilder()
                .append("POST")
                .append(" ").append(uri).append("?").append(param)
                .append("\n")
                .append(timestamp)
                .append("\n")
                .append(accessKey);

        try {
            SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(message.toString().getBytes("UTF-8"));
            String signature = Base64.encodeBase64String(rawHmac);
            return signature;
        } catch (Exception e) {
            System.out.println(e);
        }
        return null;
    }


}
