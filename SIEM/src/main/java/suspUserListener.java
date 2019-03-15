import com.espertech.esper.client.EventBean;

public class suspUserListener extends ftpListeners{
	public suspUserListener() {
		super();
	}
	public void update(EventBean[] newData, EventBean[] oldData) {
    		System.out.println(getCountAndTimestamp()+" User: "+newData[0].get("user")+" failed more than 19 times");
//    	System.out.println(newData.length);
    }
}
