import static org.apache.commons.io.FilenameUtils;
import org.apache.commons.fileupload.FileItem;

public class Decorator {

    public void decorator(HttpServletRequest request) {
            ServletFileUpload sfu = new ServletFileUpload();
            FileItem[] files = sfu.parseRequest(request);
            for (FileItem file : files) {
                System.out.println(file.getName());
            }
    }
}