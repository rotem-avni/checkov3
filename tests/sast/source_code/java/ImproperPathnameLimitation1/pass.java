import static org.apache.commons.io.FilenameUtils;

public class Decorator {

    public static void main(String[] args) {
        org.apache.commons.io.FilenameUtils.generalize(args[0]);
    }
}