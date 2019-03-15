import java.time.LocalTime;

public class EPLhttpEventConfig {

	private String type; 
	private String sourceip; 
	private String wantedDocument; 
	
	private String timeStamp;
	private long counter;

	public EPLhttpEventConfig(String type, String sourceip, String wantedDocument, String timeStamp, long counter) {
		if (type == "GET" || type == "POST") {
			this.type = type;
		} else {
			this.type = "GET";
		}
		this.sourceip = sourceip;
		this.wantedDocument = wantedDocument;
		this.timeStamp = timeStamp;
		this.counter = counter;
	}

	public String getWantedDocument() {
		return wantedDocument;
	}

	public void setWantedDocument(String wantedDocument) {
		this.wantedDocument = wantedDocument;
	}

	public String getSourceip() {
		return sourceip;
	}

	public void setSourceip(String sourceip) {
		this.sourceip = sourceip;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
	
	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}
	
	public String getTimeStamp() {
		return timeStamp;
	}
	
	public long getCounter() {
		return counter;
	}
	
	public void setCounter(long counter) {
		this.counter = counter;
	}
	
}