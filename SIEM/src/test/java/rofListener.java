import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.UpdateListener;

public class rofListener extends ftpListeners implements UpdateListener {
	public rofListener(){
		super();
	}
	public void update(EventBean[] newData, EventBean[] oldData) {
    	for(int i=0;i<newData.length;i++)
    		System.out.println(getCountAndTimestamp()+" Source: "+newData[i].get("source")+" RoF: "+newData[i].get("failrate"));
//    	System.out.println(newData.length);
    }
}
