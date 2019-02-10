import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public class infoHelper {
	  
	  private static infoHelper instance;
	  //private LocalTime timeStamp;
	  private final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");
	  private final DateTimeFormatter dtfMilli = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

	  private long counter = 0;

	  private infoHelper () {}
	  
	  public static synchronized infoHelper getInstance () {
		  
	    if (infoHelper.instance == null) {
	    	infoHelper.instance = new infoHelper();
	      
	    }
	    return infoHelper.instance;
	  }
	  
	  public long getIncrementedCounter() {
		  return this.counter++;
	  }
	  
	  public String getTimeStamp() {
		  return LocalTime.now().format(dtf);
	  }
	  
	  public String getTimeStampPrecise() {
		  return LocalTime.now().format(dtfMilli);
	  }
	}