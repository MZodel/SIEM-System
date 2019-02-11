import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.UpdateListener;

public class ftpListeners implements UpdateListener{
	
	private infoHelper ftpInfoHelper;
	
	public ftpListeners() {
		this.ftpInfoHelper =  infoHelper.getInstance();
	}

	@Override
	public void update(EventBean[] newEvents, EventBean[] oldEvents) {
		// TODO Auto-generated method stub
		
	}
	protected String getCountAndTimestamp() {
		return ftpInfoHelper.getIncrementedCounter()+" "+ ftpInfoHelper.getTimeStamp();
	}

}
