import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.UpdateListener;

public class ftpListeners implements UpdateListener{

	@Override
	public void update(EventBean[] newEvents, EventBean[] oldEvents) {
		// TODO Auto-generated method stub
		
	}
	protected String getCountAndTimestamp() {
		return "";
	}

}
