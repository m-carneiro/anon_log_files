import java.io.File;

public class AnonLogs {
  public static void main(String[] args) {
    File file = new File("log_messages_with_secrets.csv");
    if (file.exists()) {
      System.out.println("Logs file exists");
    } else {
      System.out.println("Logs file does not exist");
    }
  }
}