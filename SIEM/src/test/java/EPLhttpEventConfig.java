import java.time.LocalTime;

public class EPLhttpEventConfig {

	// -----------------First way: Find similiar targets for different
	// IPs--------------------
	// ------Paper:
	// https://ieeexplore.ieee.org/document/4313218------------------------------
	// ------Detection of HTTP-GET flood Attack Based on Analysis of Page Access
	// Behavior-----
	
	// combine all requests, order by sourceIP
	// check if different IPs have the same targets in a given time frame
	// Give a warning that those IPs are probably bots

	// Get, single IP, single target 																			DONE: ep_singleIPSingleDoc + ep_singleIPSingleDoc_TooOften
	// Get, single IP, always different targets DONE: Statement 6
	// Get, specific different IPs multiple times, single target 												DONE: ep_multipleIPSameDoc + ep_multipleIPSingleDoc_TooOften
	// Get, specific different IPs multiple times, different targets but all IPs choose same 					DONE: ep_multipleIPSameDoc + ep_multipleIPSameDoc_TooOften
	// Get, specific different IPs multiple times, always different targets DONE: Same as Statement 6
	// Get, different IPs each once, single target DONE: Statement 7
	// Get, different IPs each once, different targets but all IPs choose same DONE: Same as Statement 7+8
	// Get, different IPs each once, always different targets DONE: Statement 8

	// Difference between post/get? Is it worth it to differentiate?
	// => Post is heavier, duplicate all Get methods for Post, but with lower
	// threshold

	private String type; // GET or POST
	private String sourceip; // example: "192.168.0.1"
	private String wantedDocument; // example: either "info.html" or "/info.html", NOT both, maybe cut off data from
									// post, e.g. "/action_page.php?foo=bar&bar=baz", cut off "?" onwards
	
	private LocalTime timeStamp;
	private long counter;

	public EPLhttpEventConfig(String type, String sourceip, String wantedDocument, LocalTime timeStamp, long counter) {
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
	
	public void setTimeStamp(LocalTime timeStamp) {
		this.timeStamp = timeStamp;
	}
	
	public LocalTime getTimeStamp() {
		return timeStamp;
	}
	
	public long getCounter() {
		return counter;
	}
	
	public void setCounter(long counter) {
		this.counter = counter;
	}
	
}