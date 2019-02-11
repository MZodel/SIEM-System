import com.espertech.esper.client.EPServiceProvider;
import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.UpdateListener;

public class attackListener extends ftpListeners implements UpdateListener {
	EPServiceProvider engine;
	private infoHelper ftpInfoHelper;
	
	public attackListener(EPServiceProvider engine) {
		this.engine=engine;
		this.ftpInfoHelper = infoHelper.getInstance();
	}
	public void update(EventBean[] newData, EventBean[] oldData) {
    	for(int i=0;i<newData.length;i++) {
    		System.out.println(getCountAndTimestamp()+" Source: "+newData[i].get("source")+" is an attacker");
    		engine.getEPRuntime().sendEvent(new attackers(newData[i].get("source")+"",
    										ftpInfoHelper.getTimeStamp(),
    										ftpInfoHelper.getIncrementedCounter(),
    										"bruteforce"));
    	}    		
    }
}
