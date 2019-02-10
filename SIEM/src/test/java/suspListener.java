import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.UpdateListener;

public class suspListener extends ftpListeners{

	@Override
	public void update(EventBean[] newEvents, EventBean[] oldEvents) {
		System.out.println(getCountAndTimestamp()+" Source: "+newEvents[0].get("source")+" failed more than 19 times");

	}

}
