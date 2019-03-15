
public class successAttempt {
	private String source;
	private String user;
	
	public successAttempt(String ip, String newUser) {
		source=ip;
		user=newUser;
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
		return "Event Success: Source IP: "+source+" User: "+user;
	}
}
