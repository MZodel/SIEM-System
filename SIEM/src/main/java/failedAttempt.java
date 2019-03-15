
public class failedAttempt {
	private String source;
	private String user;
	
	public failedAttempt(String ip, String nextInt) {
		source=ip;
		user=nextInt;
	}
	public String getSource() {
		return source;
	}
	public void setSource(String source) {
		this.source = source;
	}
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	@Override
	public String toString() {
		return "Event Fail: Source IP: "+source+" User: "+user;
	}
}
