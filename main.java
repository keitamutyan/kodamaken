import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class main {
    public static void main(String[] args) {
        String targetAddress = "192.168.0.8";
        int targetPort = 9876;
        String message = "Hello, UDP!";

        try (DatagramSocket socket = new DatagramSocket()) {
            byte[] sendBuffer = message.getBytes();

            InetAddress targetInetAddress = InetAddress.getByName(targetAddress);

            DatagramPacket packet = new DatagramPacket(sendBuffer, sendBuffer.length, targetInetAddress, targetPort);

            socket.send(packet);
            System.out.println("メッセージを送信しました: " +  message +" -> " + targetAddress + ":" + targetPort);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
