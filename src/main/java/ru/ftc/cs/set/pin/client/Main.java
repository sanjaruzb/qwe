package ru.ftc.cs.set.pin.client;

import ru.ftc.cs.cam_rs.crypto.session.SetPinCryptoSession;
import ru.ftc.cs.cam_rs.crypto.session.cmn.CharsRef;
import ru.ftc.cs.cam_rs.crypto.session.cmn.SecureJson;
import ru.ftc.cs.cam_rs.crypto.session.cmn.SecureString;

import java.io.Console;
import java.util.Map;

import static java.util.Objects.isNull;

public class Main {



    @SuppressWarnings("unchecked")
    public static void main(String[] args) {
        try {


            Config cfg = new Config();
            System.out.println("set-pin test client started%n");

            String acctId  = "58858822618840560061107005";
            String panTail = "9135";
            String acpt    = acctId + "=" + panTail;

            char[] JavaCharArray = new char[4];
            JavaCharArray[0] = '1';
            JavaCharArray[1] = '2';
            JavaCharArray[2] = '3';
            JavaCharArray[3] = '5';

            char[] pin     = JavaCharArray;

            Client sender = new Client(cfg);

            try (CharsRef pinRef = CharsRef.wrap(pin);

                 SetPinCryptoSession producerCryptoSession = new SetPinCryptoSession();

                 SecureJson producerPubKey = producerCryptoSession.exportEphemeralPublicKeyAsJwk();

                 SecureJson createPinSessionReq = SecureJson.copy("acpt", acpt, "appEphemPubKey", producerPubKey.getMap());

                 SecureJson createPinSessionRes = sender.sendCreatePinSession(createPinSessionReq);

                 SecureString sessionId = (SecureString) createPinSessionRes.getMap().get("id");

                 SecureJson consumerPubKey = SecureJson.copy((Map<String, Object>) createPinSessionRes.getMap().get("camrsEphemPubKey"));

                 SecureJson producerSecretPayload = SecureJson.copy("pinCode", SecureString.wrap(pinRef));

                 SecureString producerJweCompactSerialization = producerCryptoSession
                         .setSessionId(sessionId)
                         .generateContentEncryptionKey(consumerPubKey)
                         .createJwe(producerSecretPayload)) {

                sender.sendSetPin(sessionId, producerJweCompactSerialization);



                System.out.println("b");
                System.out.println(createPinSessionReq.toInsecureString());
                System.out.println(createPinSessionRes.toInsecureString());
                System.out.println(producerPubKey.toInsecureString());
                System.out.println(consumerPubKey.toInsecureString());
                System.out.println(producerJweCompactSerialization.toInsecure());
                System.out.println("e");
            }

            System.out.println("client closed%n");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
