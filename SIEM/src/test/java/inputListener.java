import com.espertech.esper.client.EventBean;

public class inputListener extends ftpListeners {
        public void update(EventBean[] newData, EventBean[] oldData) {
        	for(int i=0;i<newData.length;i++)
        		System.out.println(getCountAndTimestamp()+" Source: "+newData[i].get("source")+" User: "+newData[i].get("user"));
//        	System.out.println(newData.length);
        }
	}