public class CommandSafe {
    public void run() throws Exception {
        ProcessBuilder pb = new ProcessBuilder("ls", "-la");
        pb.start();
    }
}
