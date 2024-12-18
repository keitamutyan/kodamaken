import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class Server {
    public static void main(String[] args) {
        int port = 9876; // リッスンするポート番号

        try (DatagramSocket socket = new DatagramSocket(port)) {
            byte[] receiveBuffer = new byte[1024];
            System.out.println("UDP受信サーバーがポート " + port + " で待機中...");

            while (true) {
                DatagramPacket packet = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                socket.receive(packet);
                String receivedMessage = new String(packet.getData(), 0, packet.getLength());
                System.out.println("受信したメッセージ: " + receivedMessage);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}