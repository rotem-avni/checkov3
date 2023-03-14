import static org.apache.commons.io.FilenameUtils;
import org.apache.commons.fileupload.FileItem;

public class Decorator {

    public void decorator(HttpServletRequest request) {
            Parameter param = request.getParameter('param');
            String rem = org.apache.commons.io.FilenameUtils.getName(param);
            new java.io.FileReader(rem);
    }
}