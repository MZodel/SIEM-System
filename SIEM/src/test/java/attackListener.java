import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.UpdateListener;

public class attackListener extends ftpListeners implements UpdateListener {
	public void update(EventBean[] newData, EventBean[] oldData) {
    	for(int i=0;i<newData.length;i++)
    		System.out.println(getCountAndTimestamp()+" Source: "+newData[i].get("source")+" is an attacker");
//    	System.out.println(newData.length);
    }
}
