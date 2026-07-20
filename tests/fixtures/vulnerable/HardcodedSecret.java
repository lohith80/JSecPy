public class HardcodedSecret {
    private String password = "S3cr3tP@ssw0rd!";
    String awsKey = "AKIAIOSFODNN7EXAMPLE";

    public String get() {
        return password + awsKey;
    }
}
